// Package k3stest runs throwaway k3s clusters for heavyweight end-to-end tests.
//
// The cluster is driven through the kubectl binary inside the k3s container
// rather than through k8s.io/client-go. That is deliberate: Pomerium's own
// Kubernetes support needs no Kubernetes client libraries, and the
// testcontainers k3s module does not import them either, so staying
// client-free keeps k8s.io/* out of the module's dependency graph entirely.
package k3stest

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	tck3s "github.com/testcontainers/testcontainers-go/modules/k3s"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// Image is pinned rather than derived: the cluster is driven through the
// container's own kubectl, so there is no k8s.io/* module version to read it
// from.
const Image = "rancher/k3s:v1.36.0-k3s1"

// RequireExclusive skips t unless an env var named after the test
// (RUN_<test name>) is set. Use it for heavyweight, non-hermetic tests that
// must run on their own: they are slow, need Docker, and some mutate the
// process-global OTel tracer, which trips testenv's global-tracer guard if
// run alongside other tests. The per-test env var keeps the gate granular:
// enabling one exclusive test never enables another.
func RequireExclusive(t *testing.T) {
	t.Helper()
	envVar := "RUN_" + t.Name()
	if os.Getenv(envVar) == "" {
		t.Skipf("skipping %s: run it in isolation with %s=1 go test -run '^%s$'",
			t.Name(), envVar, t.Name())
	}
}

// DockerContext returns ctx carrying a valid noop span, which keeps the docker
// client's otelhttp transport off the global tracer provider — testenv installs
// one that panics on use. This is the same guard internal/testutil's container
// helpers use; without it any docker call made after testenv.New panics.
func DockerContext(ctx context.Context) context.Context {
	return oteltrace.ContextWithSpan(ctx, trace.ValidNoopSpan{})
}

// Run starts a k3s cluster, failing t if it cannot, and terminates it when t
// completes. Cleanups the caller registers afterwards run first, while the
// cluster is still up.
func Run(ctx context.Context, t *testing.T, opts ...testcontainers.ContainerCustomizer) *tck3s.K3sContainer {
	t.Helper()
	ctr, err := tck3s.Run(DockerContext(ctx), Image, opts...)
	require.NoError(t, err, "failed to start k3s testcontainer")
	t.Cleanup(func() {
		// Not ctx: it may already be cancelled by the time cleanup runs.
		_ = ctr.Terminate(DockerContext(context.Background()))
	})
	return ctr
}

// Kubectl runs kubectl inside the k3s container and returns its stdout,
// failing the test if it cannot be run or exits non-zero. The k3s image ships
// kubectl at /bin/kubectl, already pointed at the cluster it serves, so this
// needs neither a kubeconfig on the host nor a Kubernetes client library.
func Kubectl(ctx context.Context, t *testing.T, ctr *tck3s.K3sContainer, args ...string) string {
	t.Helper()
	// Multiplexed demuxes docker's stream framing; without it the output is
	// interleaved with per-frame headers.
	code, r, err := ctr.Exec(DockerContext(ctx), append([]string{"kubectl"}, args...), tcexec.Multiplexed())
	require.NoErrorf(t, err, "kubectl %v", args)
	out, err := io.ReadAll(r)
	require.NoErrorf(t, err, "reading output of kubectl %v", args)
	require.Zerof(t, code, "kubectl %v failed: %s", args, out)
	return strings.TrimSpace(string(out))
}
