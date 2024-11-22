package envutil

import (
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// PauseProfiling will suspend CPU and memory profiling, if started using the
// -cpuprofile and/or -memprofile test flags. The returned function will restart
// profiling when called. Existing CPU profile data is overwritten, but
// existing memory profile data is kept.
func PauseProfiling(t testing.TB) (resume func()) {
	resumeFuncs := []func(){}

	if filename := ProfileOutputPath("cpuprofile"); filename != "" {
		if _, err := os.Stat(filename); err == nil {
			pprof.StopCPUProfile()
			t.Logf("pausing cpu profiling (%s)", filename)
			resumeFuncs = append(resumeFuncs, func() {
				t.Logf("resuming cpu profiling (%s)", filename)
				f, err := os.Create(filename)
				require.NoError(t, err)
				require.NoError(t, pprof.StartCPUProfile(f))
			})
		}
	}

	if filename := ProfileOutputPath("memprofile"); filename != "" {
		rate := runtime.MemProfileRate
		runtime.MemProfileRate = 0
		t.Log("pausing memory profiling")
		resumeFuncs = append(resumeFuncs, func() {
			t.Log("resuming memory profiling")
			runtime.MemProfileRate = rate
		})
	}
	return sync.OnceFunc(func() {
		for _, f := range resumeFuncs {
			f()
		}
	})
}

// Returns the file path set by the '-test.<name>profile' flag, or empty string
// if the flag was not set.
func ProfileOutputPath(name string) string {
	outputdir := flag.Lookup("test.outputdir")
	if f := flag.Lookup("test." + name); f != nil {
		if filename := f.Value.String(); filename != "" {
			if outputdir != nil {
				filename = filepath.Join(outputdir.Value.String(), filename)
			}
			return filename
		}
	}
	return ""
}

// Returns true if the envoy binary at the given path was compiled with
// gperftools profiler support.
func EnvoyProfilerAvailable(binary string) bool {
	// There are a few symbols that will only show up if envoy is compiled with
	// tcmalloc=gperftools. Specifically, symbols defined in these headers:
	// https://github.com/gperftools/gperftools/tree/master/src/gperftools
	// The symbols are not mangled, so pick one that is unlikely to be ambiguous
	// or part of another function name.
	err := exec.Command("/usr/bin/grep", "-q", "ProfilingIsEnabledForAllThreads", binary).Run()
	return err == nil
}

func CollectEnvoyHeapProfiles(base string) error {
	combined, err := os.OpenFile(base, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer combined.Close()
	parts, _ := filepath.Glob(base + ".*.heap")
	for _, part := range parts {
		pf, err := os.Open(part)
		if err != nil {
			return err
		}
		if _, err := io.Copy(combined, pf); err != nil {
			return err
		}
		_ = pf.Close()
		if err := os.Remove(part); err != nil {
			return err
		}
	}
	return nil
}
