//go:build e2e

package downstreammtls_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

// envOr returns the value of the environment variable, or def when unset.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// workspace holds the per-run host directories bind-mounted into containers.
type workspace struct {
	root          string
	certsDir      string
	playwrightDir string
	logsDir       string
}

// newWorkspace creates artifacts/run-<ts>/{certs,playwright,logs} under the
// suite directory. It must live under the repo (not os.TempDir) so Docker
// Desktop can always bind-mount it. The run directory is removed on success
// and kept on failure, or always when E2E_KEEP_ARTIFACTS is set.
func newWorkspace(t *testing.T, suiteDir string) *workspace {
	t.Helper()
	root := filepath.Join(suiteDir, "artifacts", "run-"+strconv.FormatInt(time.Now().Unix(), 10))
	ws := &workspace{
		root:          root,
		certsDir:      filepath.Join(root, "certs"),
		playwrightDir: filepath.Join(root, "playwright"),
		logsDir:       filepath.Join(root, "logs"),
	}
	for _, dir := range []string{ws.certsDir, ws.playwrightDir, ws.logsDir} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	t.Logf("workspace: %s", root)
	t.Cleanup(func() {
		if t.Failed() || os.Getenv("E2E_KEEP_ARTIFACTS") != "" {
			t.Logf("keeping artifacts in %s", root)
			return
		}
		_ = os.RemoveAll(root)
	})
	return ws
}

// startContainer starts a container and registers its termination with
// t.Cleanup (safe to call from errgroup goroutines - it never fails the
// test itself).
func startContainer(t *testing.T, ctx context.Context, img string, opts ...testcontainers.ContainerCustomizer) (*testcontainers.DockerContainer, error) {
	t.Helper()
	ctr, err := testcontainers.Run(ctx, img, opts...)
	if ctr != nil {
		t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })
	}
	if err != nil {
		return nil, err
	}
	return ctr, nil
}

// runContainer is startContainer for the test goroutine: it fails the test on
// error. Mirrors internal/testutil.mustRunContainer.
func runContainer(t *testing.T, ctx context.Context, img string, opts ...testcontainers.ContainerCustomizer) *testcontainers.DockerContainer {
	t.Helper()
	ctr, err := startContainer(t, ctx, img, opts...)
	require.NoError(t, err, "error starting container %s", img)
	return ctr
}

// containerExitCode returns the exit code of an exited container.
// wait.ForExit only waits for the container to stop; it does not check how.
func containerExitCode(ctx context.Context, ctr *testcontainers.DockerContainer) (int, error) {
	st, err := ctr.State(ctx)
	if err != nil {
		return 0, err
	}
	return st.ExitCode, nil
}

// containerLogs returns the container's combined output for error messages.
func containerLogs(ctx context.Context, ctr *testcontainers.DockerContainer) string {
	rc, err := ctr.Logs(ctx)
	if err != nil {
		return fmt.Sprintf("(error reading logs: %v)", err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Sprintf("(error reading logs: %v)", err)
	}
	return string(b)
}

// fileLogConsumer appends container output to <dir>/<name>.log.
type fileLogConsumer struct {
	mu sync.Mutex
	f  *os.File
}

func newFileLogConsumer(t *testing.T, dir, name string) *fileLogConsumer {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name+".log"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return &fileLogConsumer{f: f}
}

func (c *fileLogConsumer) Accept(l testcontainers.Log) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _ = c.f.Write(l.Content)
}

// testLogConsumer streams container output into the test log.
type testLogConsumer struct {
	t      *testing.T
	prefix string
}

func (c *testLogConsumer) Accept(l testcontainers.Log) {
	c.t.Logf("[%s] %s", c.prefix, bytes.TrimRight(l.Content, "\n"))
}

// runHostPlaywright runs the Playwright specs with npx on the host instead of
// in a container. Required for headed mode: a visible browser cannot run
// inside the Linux container. Expects Pomerium/Keycloak published on their
// fixed in-network ports (see hostPlaywright in TestDownstreamMTLS) so the
// browser URLs are identical to container mode.
func runHostPlaywright(t *testing.T, ctx context.Context, browserDir string, env map[string]string, headed bool) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(browserDir, "node_modules")); err != nil {
		t.Log("browser/node_modules missing; installing npm dependencies...")
		runHostCommand(t, ctx, browserDir, nil, "npm", "ci", "--no-audit", "--no-fund")
	}
	// No-op when the browser is already installed.
	runHostCommand(t, ctx, browserDir, nil, "npx", "playwright", "install", "chromium")

	args := []string{"playwright", "test"}
	if headed {
		args = append(args, "--headed")
	}
	runHostCommand(t, ctx, browserDir, env, "npx", args...)
}

// runHostCommand runs a command on the host, streaming its output.
func runHostCommand(t *testing.T, ctx context.Context, dir string, env map[string]string, name string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	t.Logf("running: %s %v", name, args)
	require.NoError(t, cmd.Run(), "%s %v failed (see output above; artifacts: %s)", name, args, env["ARTIFACTS_DIR"])
}
