package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

// K3sImage returns the rancher/k3s container image whose Kubernetes version
// matches the k8s.io/* client libraries this module depends on, so a k3s server
// started for a test tracks the client automatically as the k8s.io/* modules
// are bumped — there is no separately-maintained image pin to drift out of
// sync. It fails the test if the k8s.io/api module version can't be determined.
func K3sImage(tb testing.TB) string {
	tb.Helper()
	version, err := k8sAPIModuleVersion()
	if err != nil {
		tb.Fatalf("testutil: %v", err)
	}
	img, err := K3sImageForK8sModuleVersion(version)
	if err != nil {
		tb.Fatalf("testutil: %v", err)
	}
	return img
}

// k8sAPIModuleVersion returns the k8s.io/api version required by the module's
// go.mod. It reads go.mod directly rather than debug.ReadBuildInfo because
// `go test` binaries do not embed the module dependency list (BuildInfo.Deps
// is empty), so build info can't be used to derive the version at test time.
func k8sAPIModuleVersion() (string, error) {
	gomod, err := findGoMod()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(gomod)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", gomod, err)
	}
	f, err := modfile.Parse(gomod, data, nil)
	if err != nil {
		return "", fmt.Errorf("parsing %s: %w", gomod, err)
	}
	for _, r := range f.Require {
		if r.Mod.Path == "k8s.io/api" {
			return r.Mod.Version, nil
		}
	}
	return "", fmt.Errorf("k8s.io/api not required in %s", gomod)
}

// findGoMod locates the module's go.mod by walking up from the working
// directory (where `go test` runs, i.e. the package source dir), falling back
// to the directory of this source file.
func findGoMod() (string, error) {
	starts := make([]string, 0, 2)
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		starts = append(starts, filepath.Dir(file))
	}
	for _, dir := range starts {
		for {
			candidate := filepath.Join(dir, "go.mod")
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", fmt.Errorf("go.mod not found from working directory or source path")
}

// K3sImageForK8sModuleVersion maps a k8s.io/* module version to the matching
// k3s image tag. The k8s.io modules are versioned v0.<minor>.<patch> (e.g.
// v0.36.1 is Kubernetes 1.36.1), and k3s publishes
// rancher/k3s:v1.<minor>.<patch>-k3s1. It pins the .0 patch of the minor: the
// .0 is always published once a minor is GA (unlike the exact client patch,
// which k3s may briefly lag), and running the server one patch behind the
// client is well within the supported client/server skew.
func K3sImageForK8sModuleVersion(version string) (string, error) {
	rest, ok := strings.CutPrefix(version, "v0.")
	if !ok {
		return "", fmt.Errorf("unexpected k8s.io module version %q (want v0.<minor>.<patch>)", version)
	}
	minor, _, ok := strings.Cut(rest, ".")
	if !ok || minor == "" {
		return "", fmt.Errorf("cannot parse minor from k8s.io module version %q", version)
	}
	return fmt.Sprintf("rancher/k3s:v1.%s.0-k3s1", minor), nil
}
