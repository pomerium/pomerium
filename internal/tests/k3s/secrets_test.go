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
// needed. The upstream is traefik/whoami, which echoes request headers.
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
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	whoamiImage       = "traefik/whoami:v1.11.0"

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
  name: whoami
  labels: {app: whoami}
spec:
  containers:
  - name: whoami
    image: ` + whoamiImage + `
    ports: [{containerPort: 80}]
---
apiVersion: v1
kind: Service
metadata:
  name: whoami
spec:
  selector: {app: whoami}
  ports: [{port: 80}]
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
      to: http://whoami.default.svc.cluster.local
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
	k3stest.Kubectl(ctx, t, k3sCtr, "wait", "--for=condition=Ready", "pod/whoami", "pod/pomerium", "--timeout=5m")

	port, err := k3sCtr.MappedPort(k3stest.DockerContext(ctx), pomeriumNodePort+"/tcp")
	require.NoError(t, err)
	host, err := k3sCtr.Host(k3stest.DockerContext(ctx))
	require.NoError(t, err)
	baseURL := fmt.Sprintf("http://%s:%s/", host, port.Port())

	// probe returns the response status (0 if the request itself failed) and,
	// on a 200, the headers whoami saw, keyed by lower-cased name.
	probe := func() (int, map[string]string) {
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, baseURL, nil)
		require.NoError(t, err)
		req.Host = secretsRouteHost
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, nil
		}
		defer func() {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, nil
		}
		// whoami writes one "Name: value" line per request header.
		hdrs := map[string]string{}
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if k, v, ok := strings.Cut(sc.Text(), ": "); ok {
				hdrs[strings.ToLower(k)] = v
			}
		}
		if sc.Err() != nil {
			return 0, nil
		}
		return resp.StatusCode, hdrs
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
			status, hdrs := probe()
			return status == http.StatusOK &&
				hdrs["x-secret-plain"] == "plain="+v &&
				hdrs["x-secret-projected"] == "projected="+v
		}, 2*time.Minute, time.Second, "upstream should see secret value %q through both mounts", v)
	}

	// Removing the key makes kubelet delete the projected files; once the
	// stale grace elapses, requests fail closed with a 503 instead of reaching
	// the upstream with a stale or empty header.
	k3stest.Kubectl(ctx, t, k3sCtr, "patch", "secret", "upstream-token",
		"--type=json", "-p", `[{"op":"remove","path":"/data/token"}]`)
	require.Eventually(t, func() bool {
		status, _ := probe()
		return status == http.StatusServiceUnavailable
	}, 2*time.Minute, time.Second, "requests should fail closed once the key is removed")
}
