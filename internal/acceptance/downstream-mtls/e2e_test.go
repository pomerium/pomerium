//go:build e2e

// Package downstreammtls_test is an e2e suite for Pomerium's global
// downstream_mtls settings (client certificate requirements for end users).
//
// Unlike the parent acceptance suite (docker-compose, Pomerium built from
// source, Playwright on the host), this suite uses testcontainers-go to
// orchestrate every component and tests the OFFICIAL published Pomerium image
// with its configuration injected as a volume mount:
//
//   - one-shot OpenSSL container generating server + client certificates
//     (wrapping the parent suite's scripts)
//   - Keycloak as a real OIDC IdP (parent suite's realm fixtures)
//   - traefik/whoami as the upstream, echoing request headers
//   - pomerium/pomerium:main (POMERIUM_IMAGE overrides)
//   - a Playwright container running the browser specs mounted from ./browser
//
// Run with:
//
//	make test        # or: go test -tags e2e -v -timeout 30m ./...
//
// Prerequisites: Docker and Go only. See README.md for debugging tips.
package downstreammtls_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/sync/errgroup"
)

const (
	defaultPomeriumImage = "pomerium/pomerium:main"
	defaultKeycloakImage = "quay.io/keycloak/keycloak:26.5.2"
	defaultUpstreamImage = "traefik/whoami:v1.11"
	// Must match the exact @playwright/test version pinned in
	// browser/package.json (the image ships the matching browser builds).
	defaultPlaywrightImage = "mcr.microsoft.com/playwright:v1.61.1-noble"

	keycloakHost    = "keycloak.localhost.pomerium.io"
	authenticateURL = "https://authenticate.localhost.pomerium.io:8443"
	mtlsURL         = "https://mtls.localhost.pomerium.io:8443"
)

func TestDownstreamMTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	ctx := t.Context()

	suiteDir, err := os.Getwd()
	require.NoError(t, err)
	// Shared assets from the parent acceptance suite: OpenSSL scripts and
	// Keycloak realm fixtures (single source of truth, mounted read-only).
	parentDir := filepath.Dir(suiteDir)

	ws := newWorkspace(t, suiteDir)

	nw, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = nw.Remove(context.Background()) })

	// Phase 1: certificate generation, Keycloak and the upstream have no
	// interdependencies - start them in parallel.
	eg, egCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		certgen, err := startContainer(t, egCtx, "alpine:3.21",
			testcontainers.WithCmd("/bin/sh", "/scripts/gen-certs.sh"),
			testcontainers.WithEnv(map[string]string{"CERTS_DIR": "/certs"}),
			testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
				hc.Binds = append(hc.Binds,
					filepath.Join(suiteDir, "scripts")+":/scripts:ro",
					filepath.Join(parentDir, "scripts")+":/parent-scripts:ro",
					ws.certsDir+":/certs",
				)
			}),
			testcontainers.WithWaitStrategyAndDeadline(3*time.Minute, wait.ForExit()),
		)
		if err != nil {
			return fmt.Errorf("cert-gen: %w", err)
		}
		if code, err := containerExitCode(egCtx, certgen); err != nil {
			return fmt.Errorf("cert-gen state: %w", err)
		} else if code != 0 {
			return fmt.Errorf("cert-gen exited with code %d; logs:\n%s", code, containerLogs(egCtx, certgen))
		}
		return nil
	})
	eg.Go(func() error {
		// Settings mirror internal/acceptance/docker-compose.yml.
		_, err := startContainer(t, egCtx, envOr("KEYCLOAK_IMAGE", defaultKeycloakImage),
			tcnetwork.WithNetwork([]string{keycloakHost}, nw),
			testcontainers.WithCmd("start-dev", "--import-realm", "--health-enabled=true", "--http-port=8080"),
			testcontainers.WithEnv(map[string]string{
				"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
				"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
				"KC_HTTP_ENABLED":             "true",
				"KC_HOSTNAME":                 keycloakHost,
				"KC_HOSTNAME_STRICT":          "false",
				"KC_PROXY_HEADERS":            "xforwarded",
			}),
			testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
				hc.Binds = append(hc.Binds,
					filepath.Join(parentDir, "keycloak")+":/opt/keycloak/data/import:ro",
				)
			}),
			// 9000 is the management interface serving /health/ready; the
			// HTTP wait strategy probes it through the host-mapped port.
			testcontainers.WithExposedPorts("8080/tcp", "9000/tcp"),
			testcontainers.WithLogConsumers(newFileLogConsumer(t, ws.logsDir, "keycloak")),
			testcontainers.WithWaitStrategyAndDeadline(5*time.Minute,
				wait.ForHTTP("/health/ready").WithPort("9000/tcp").WithStartupTimeout(5*time.Minute)),
		)
		if err != nil {
			return fmt.Errorf("keycloak: %w", err)
		}
		return nil
	})
	eg.Go(func() error {
		// traefik/whoami is built FROM scratch (no shell), so wait on its
		// startup log line rather than a port or HTTP probe.
		_, err := startContainer(t, egCtx, envOr("UPSTREAM_IMAGE", defaultUpstreamImage),
			tcnetwork.WithNetwork([]string{"upstream"}, nw),
			testcontainers.WithWaitStrategyAndDeadline(2*time.Minute, wait.ForLog("Starting up on port")),
		)
		if err != nil {
			return fmt.Errorf("upstream: %w", err)
		}
		return nil
	})
	require.NoError(t, eg.Wait())

	// Phase 2: Pomerium (the official published image) - needs the generated
	// certificates on disk and Keycloak's OIDC discovery endpoint up.
	pomerium := runContainer(t, ctx, envOr("POMERIUM_IMAGE", defaultPomeriumImage),
		tcnetwork.WithNetwork([]string{
			"authenticate.localhost.pomerium.io",
			"mtls.localhost.pomerium.io",
		}, nw),
		testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
			hc.Binds = append(hc.Binds,
				filepath.Join(suiteDir, "pomerium", "config.yaml")+":/pomerium/config.yaml:ro",
				ws.certsDir+":/certs:ro",
			)
		}),
		testcontainers.WithExposedPorts("8443/tcp"),
		testcontainers.WithLogConsumers(newFileLogConsumer(t, ws.logsDir, "pomerium")),
		// /healthz is a control-plane route exempt from the mTLS default
		// deny, so no client certificate is needed under the default
		// policy_with_default_deny mode. A future reject_connection variant
		// MUST present a client certificate here via tls.Config.Certificates
		// (or use wait.ForListeningPort("8443/tcp").SkipInternalCheck() -
		// the distroless image has no /bin/sh for the internal check).
		testcontainers.WithWaitStrategyAndDeadline(3*time.Minute,
			wait.ForHTTP("/healthz").WithPort("8443/tcp").
				WithTLS(true, &tls.Config{InsecureSkipVerify: true}).
				WithStartupTimeout(3*time.Minute)),
	)
	if port, err := pomerium.MappedPort(ctx, "8443/tcp"); err == nil {
		t.Logf("pomerium reachable from the host at https://localhost:%s (in-network port 8443)", port.Port())
	}

	// Phase 3: containerized Playwright runner. The browser project is
	// mounted read-only and copied inside the container so npm never writes
	// into the repo; reports and traces land in the workspace via /artifacts.
	runScript := `set -x
cp -r /suite /work || exit 1
cd /work || exit 1
npm ci --no-audit --no-fund || npm ci --no-audit --no-fund || exit 1
npx playwright test
rc=$?
chmod -R a+rwX /artifacts || true
exit $rc`
	runner := runContainer(t, ctx, envOr("PLAYWRIGHT_IMAGE", defaultPlaywrightImage),
		tcnetwork.WithNetwork([]string{"playwright"}, nw),
		testcontainers.WithCmd("/bin/bash", "-c", runScript),
		testcontainers.WithEnv(map[string]string{
			"CI":                 "true",
			"ARTIFACTS_DIR":      "/artifacts",
			"CERTS_DIR":          "/certs/mtls",
			"MTLS_URL":           mtlsURL,
			"AUTHENTICATE_URL":   authenticateURL,
			"TEST_USER_EMAIL":    "alice@company.com",
			"TEST_USER_PASSWORD": "password123",
		}),
		testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
			hc.ShmSize = 2 << 30 // Chromium needs generous shared memory
			hc.Binds = append(hc.Binds,
				filepath.Join(suiteDir, "browser")+":/suite:ro",
				ws.certsDir+":/certs:ro",
				ws.playwrightDir+":/artifacts",
			)
		}),
		testcontainers.WithLogConsumers(&testLogConsumer{t: t, prefix: "playwright"}),
		testcontainers.WithWaitStrategyAndDeadline(15*time.Minute, wait.ForExit()),
	)

	code, err := containerExitCode(ctx, runner)
	require.NoError(t, err)
	require.Zero(t, code,
		"playwright specs failed (exit code %d); HTML report, traces and container logs: %s", code, ws.root)
}
