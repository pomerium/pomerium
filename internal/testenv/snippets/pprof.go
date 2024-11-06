package snippets

import (
	"flag"
	"os"
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

	outputdir := flag.Lookup("test.outputdir")
	if f := flag.Lookup("test.cpuprofile"); f != nil {
		filename := f.Value.String()
		if outputdir != nil {
			filename = filepath.Join(outputdir.Value.String(), filename)
		}
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

	if f := flag.Lookup("test.memprofile"); f != nil {
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
