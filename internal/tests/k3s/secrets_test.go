// Package k3s_test holds end-to-end tests that run Pomerium as a pod in a
// throwaway k3s cluster.
//
// TestSecretInjection_K3s covers secret injection: a real
// kubelet projects a Kubernetes Secret into a Pomerium pod, and rotating the
// Secret must reach the upstream as a changed request header with no Pomerium
// restart or config reload.
//
// Pomerium runs in-cluster because only a pod can mount a Secret volume. The
// test cross-compiles a linux binary of this checkout and hands it to a stock
// distroless pod through a hostPath on the k3s node, so no docker build is
// needed. The upstream is pomerium/verify, whose /headers endpoint echoes the
// request headers it received as JSON.
//
// The Secret is mounted twice — through a plain `secret` volume and through a
// `projected` volume — because both are written by kubelet's atomic writer,
// which publishes an update by swapping the `..data` symlink rather than
// rewriting the file. That swap is exactly what the file provider must notice.
// Kubelet's pod sync is shortened to a few seconds so each rotation lands
// quickly; the mechanism is unchanged.
//
// Gated by k3stest.RequireExclusive (slow, needs Docker and network access to
// pull the pod images). Run it via:
//
//	make test-e2e-k3s-secrets
//
// or directly:
//
//	RUN_TestSecretInjection_K3s=1 go test -timeout=20m \
//	    -run '^TestSecretInjection_K3s$' ./internal/tests/k3s/

package k3s_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/testutil/k3stest"
)

const (
	// Same base as the dev image built by scripts/build-dev-docker.bash.
	pomeriumBaseImage = "gcr.io/distroless/base-nossl-debian12:debug"
	verifyImage       = "pomerium/verify:sha-6bdce79"

	pomeriumNodePort = "30080"
	secretsRouteHost = "echo.example.com"
	secretsNodeDir   = "/opt/pomerium"
)

// secretsK3sManifest deploys the upstream, the Secret, and a Pomerium pod
// that mounts that Secret both as a `secret` volume and as a `projected`
// volume, each bound to its own secret reference and request header.
const secretsK3sManifest = `
apiVersion: v1
kind: Secret
metadata:
  name: upstream-token
stringData:
  token: v1
---
apiVersion: v1
kind: Pod
metadata:
  name: verify
  labels: {app: verify}
spec:
  containers:
  - name: verify
    image: ` + verifyImage + `
    ports: [{containerPort: 8000}]
---
apiVersion: v1
kind: Service
metadata:
  name: verify
spec:
  selector: {app: verify}
  ports: [{port: 80, targetPort: 8000}]
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: pomerium-config
data:
  config.yaml: |
    address: :8080
    insecure_server: true
    shared_secret: UYgnt8bxxK5G2sFaNzyqi5Z+OgF8m2akNc0xdQx718w=
    cookie_secret: UYgnt8bxxK5G2sFaNzyqi5Z+OgF8m2akNc0xdQx718w=
    secrets:
      defaults:
        refresh: 1h
        stale_grace: 2s
        negative_ttl: 1s
      bindings:
        plain:
          url: file:///secrets/plain/token
        projected:
          url: file:///secrets/projected/token
    routes:
    - from: http://` + secretsRouteHost + `
      to: http://verify.default.svc.cluster.local
      allow_public_unauthenticated_access: true
      set_request_headers:
        X-Secret-Plain: plain=${secret.plain}
        X-Secret-Projected: projected=${secret.projected}
---
apiVersion: v1
kind: Pod
metadata:
  name: pomerium
  labels: {app: pomerium}
spec:
  containers:
  - name: pomerium
    image: ` + pomeriumBaseImage + `
    command: [` + secretsNodeDir + `/pomerium, -config, /pomerium/config.yaml]
    ports: [{containerPort: 8080}]
    readinessProbe:
      tcpSocket: {port: 8080}
      periodSeconds: 1
    volumeMounts:
    - {name: bin, mountPath: ` + secretsNodeDir + `, readOnly: true}
    - {name: config, mountPath: /pomerium, readOnly: true}
    - {name: plain, mountPath: /secrets/plain, readOnly: true}
    - {name: projected, mountPath: /secrets/projected, readOnly: true}
    - {name: tmp, mountPath: /tmp}
  volumes:
  - name: bin
    hostPath: {path: ` + secretsNodeDir + `, type: Directory}
  - name: config
    configMap: {name: pomerium-config}
  - name: plain
    secret: {secretName: upstream-token}
  - name: projected
    projected:
      sources:
      - secret: {name: upstream-token}
  - name: tmp
    emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: pomerium
spec:
  type: NodePort
  selector: {app: pomerium}
  ports: [{port: 8080, nodePort: ` + pomeriumNodePort + `}]
`

// buildLinuxPomerium builds this checkout's pomerium binary for linux on the
// docker daemon's architecture, through the Makefile's build-go target so it
// carries the same build tags and linker flags as every other build, and
// returns its path. It returns an error rather than failing t so that it can
// run concurrently with the cluster start.
func buildLinuxPomerium(ctx context.Context, dir string) (string, error) {
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		return "", err
	}
	defer cli.Close()
	ver, err := cli.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, "make", "build-go", "BINDIR="+dir)
	cmd.Dir = "../../.." // module root; go test runs in the package directory
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+ver.Arch)
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("building linux/%s pomerium: %w: %s", ver.Arch, err, b)
	}
	return filepath.Join(dir, "pomerium"), nil
}

func TestSecretInjection_K3s(t *testing.T) {
	k3stest.RequireExclusive(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// The build and the cluster start are independent; overlap them.
	var binary string
	var build errgroup.Group
	build.Go(func() (err error) {
		binary, err = buildLinuxPomerium(k3stest.DockerContext(ctx), t.TempDir())
		return err
	})

	k3sCtr := k3stest.Run(ctx, t,
		testcontainers.WithCmdArgs("--kubelet-arg=sync-frequency=5s"),
		testcontainers.WithExposedPorts(pomeriumNodePort+"/tcp"))
	t.Cleanup(func() {
		// Not ctx: it may already be cancelled by the time cleanup runs.
		if t.Failed() {
			t.Logf("pomerium logs:\n%s", k3stest.Kubectl(context.Background(), t, k3sCtr, "logs", "pomerium", "--tail=200"))
		}
	})
	require.NoError(t, build.Wait())

	require.NoError(t, k3sCtr.CopyFileToContainer(k3stest.DockerContext(ctx), binary, secretsNodeDir+"/pomerium", 0o755))
	require.NoError(t, k3sCtr.CopyToContainer(k3stest.DockerContext(ctx), []byte(secretsK3sManifest), "/tmp/manifest.yaml", 0o644))
	k3stest.Kubectl(ctx, t, k3sCtr, "apply", "-f", "/tmp/manifest.yaml")
	// The first run pulls both images into the node.
	k3stest.Kubectl(ctx, t, k3sCtr, "wait", "--for=condition=Ready", "pod/verify", "pod/pomerium", "--timeout=5m")

	port, err := k3sCtr.MappedPort(k3stest.DockerContext(ctx), pomeriumNodePort+"/tcp")
	require.NoError(t, err)
	host, err := k3sCtr.Host(k3stest.DockerContext(ctx))
	require.NoError(t, err)
	headersURL := fmt.Sprintf("http://%s:%s/headers", host, port.Port())

	// probe returns the response status (0 if the request itself failed) and
	// body.
	probe := func() (int, []byte) {
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, headersURL, nil)
		require.NoError(t, err)
		req.Host = secretsRouteHost
		// Ask for JSON so that a Pomerium denial carries its reason.
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, nil
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return 0, nil
		}
		return resp.StatusCode, body
	}

	// Each value must reach the upstream through both mounts before the next
	// rotation: repeated rotations prove the watcher follows every ..data
	// swap, not just the first.
	for _, v := range []string{"v1", "v2", "v3"} {
		if v != "v1" {
			k3stest.Kubectl(ctx, t, k3sCtr, "patch", "secret", "upstream-token",
				"-p", fmt.Sprintf(`{"stringData":{"token":%q}}`, v))
		}
		require.Eventuallyf(t, func() bool {
			status, body := probe()
			var hdrs http.Header
			return status == http.StatusOK &&
				json.Unmarshal(body, &hdrs) == nil &&
				hdrs.Get("X-Secret-Plain") == "plain="+v &&
				hdrs.Get("X-Secret-Projected") == "projected="+v
		}, 2*time.Minute, time.Second, "upstream should see secret value %q through both mounts", v)
	}

	// Removing the key makes kubelet delete the projected files; once the
	// stale grace elapses, requests fail closed instead of reaching the
	// upstream with a stale or empty header. The reason tells this denial
	// apart from a 503 that Envoy returns when the upstream is unavailable.
	k3stest.Kubectl(ctx, t, k3sCtr, "patch", "secret", "upstream-token",
		"--type=json", "-p", `[{"op":"remove","path":"/data/token"}]`)
	require.Eventually(t, func() bool {
		status, body := probe()
		var denial struct{ Error string }
		return status == http.StatusServiceUnavailable &&
			json.Unmarshal(body, &denial) == nil &&
			denial.Error == "secret unavailable"
	}, 2*time.Minute, time.Second, "requests should fail closed once the key is removed")

	// A restart would reread the files at startup and pass every check above
	// without the watcher, so the same Pomerium process must have served them
	// all.
	restarts := k3stest.Kubectl(ctx, t, k3sCtr, "get", "pod", "pomerium",
		"-o", "jsonpath={.status.containerStatuses[0].restartCount}")
	require.Equal(t, "0", restarts, "pomerium must not restart during the test")
}
