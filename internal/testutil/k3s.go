package testutil

import (
	"fmt"
	"runtime/debug"
	"strings"
	"testing"
)

// K3sImage returns the rancher/k3s container image whose Kubernetes version
// matches the k8s.io/* client libraries this test binary is built against, so a
// k3s server started for a test tracks the client automatically as the k8s.io/*
// modules are bumped — there is no separately-maintained image pin to drift out
// of sync. It fails the test if the k8s.io/api module version can't be
// determined (e.g. the binary does not link k8s.io/api).
func K3sImage(tb testing.TB) string {
	tb.Helper()
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		tb.Fatal("testutil: no build info available; cannot derive k3s image")
	}
	for _, dep := range bi.Deps {
		if dep.Path == "k8s.io/api" {
			img, err := K3sImageForK8sModuleVersion(dep.Version)
			if err != nil {
				tb.Fatalf("testutil: %v", err)
			}
			return img
		}
	}
	tb.Fatal("testutil: k8s.io/api not found in build info; cannot derive k3s image")
	return ""
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
