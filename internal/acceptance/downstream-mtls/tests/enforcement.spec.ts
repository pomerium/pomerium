/**
 * Group D - enforcement modes (downstream_mtls.enforcement).
 * Test plan: Client Certificates (mTLS), TC-CC-12..14.
 */

import { test, expect } from "@playwright/test";
import { setTimeout as sleep } from "node:timers/promises";
import {
  expectDenied495,
  expectLoginRedirect,
  getNoRedirect,
  withCert,
} from "../helpers/api.js";
import { certPaths } from "../helpers/mtls.js";
import { rawTLSProbe } from "../helpers/raw-tls.js";
import { startPomerium } from "../setup/containers.js";
import { buildRoute, CONTAINER_CERTS, generateConfig } from "../setup/pomerium-config.js";
import { MTLS_HOSTNAME, MTLS_URL } from "../setup/constants.js";

test.describe("Group D: enforcement modes", () => {
  test("TC-CC-12: policy_with_default_deny - 495 on routes, internal pages exempt", async () => {
    const pomerium = await startPomerium({
      configFile: generateConfig({
        name: "enforcement-default-deny",
        downstreamMtls: {
          ca_file: CONTAINER_CERTS.rootCA,
          enforcement: "policy_with_default_deny",
        },
      }),
    });
    try {
      await withCert(null, async (ctx) => {
        // User-defined route: denied with the 495 error page.
        await expectDenied495(ctx, MTLS_URL);
        // Internal Pomerium pages remain reachable without a certificate.
        const healthz = await ctx.get(`${MTLS_URL}/healthz`);
        expect(healthz.status()).toBe(200);
        const internal = await getNoRedirect(ctx, `${MTLS_URL}/.pomerium/`);
        expect(internal.status()).not.toBe(495);
      });
    } finally {
      await pomerium.stop();
    }
  });

  test("TC-CC-13: policy - no default deny; explicit invalid_client_certificate rule blocks", async () => {
    const pomerium = await startPomerium({
      configFile: generateConfig({
        name: "enforcement-policy",
        downstreamMtls: { ca_file: CONTAINER_CERTS.rootCA, enforcement: "policy" },
        routes: [
          // Route with an explicit deny rule for untrusted client certs.
          buildRoute({
            prefix: "/guarded",
            policy: [
              { deny: { or: [{ invalid_client_certificate: true }] } },
              { allow: { or: [{ authenticated_user: true }] } },
            ],
          }),
          // Route with a normal policy only.
          buildRoute({}),
        ],
      }),
    });
    try {
      await withCert(null, async (ctx) => {
        // Without the default deny rule, a certificate-less request is no
        // longer blocked at the mTLS layer - normal policy applies (redirect
        // into the login flow, not 495).
        await expectLoginRedirect(ctx, MTLS_URL);

        // The explicit invalid_client_certificate deny rule still blocks.
        await expectDenied495(ctx, `${MTLS_URL}/guarded`);
      });

      // With a trusted certificate the guarded route is not blocked by the
      // deny rule (it proceeds to the normal login flow).
      await withCert("valid", (ctx) => expectLoginRedirect(ctx, `${MTLS_URL}/guarded`));
    } finally {
      await pomerium.stop();
    }
  });

  test("TC-CC-14: reject_connection - TLS handshake rejected, all routes, no authorize logs", async () => {
    const pomerium = await startPomerium({
      configFile: generateConfig({
        name: "enforcement-reject",
        downstreamMtls: {
          ca_file: CONTAINER_CERTS.rootCA,
          enforcement: "reject_connection",
        },
      }),
      // /healthz itself requires a client certificate in this mode.
      wait: "client-cert-tls",
    });
    try {
      // Let the readiness probe's own log entries drain before capturing.
      await sleep(1_000);
      pomerium.clearLogs();

      // No certificate: the connection is rejected at the TLS layer - there
      // is no HTTP response at all (a browser would show
      // ERR_BAD_SSL_CLIENT_AUTH_CERT). This applies to internal routes too
      // (the probe requests /healthz, which TC-CC-12 proved is exempt in the
      // default mode).
      const noCert = await rawTLSProbe({ servername: MTLS_HOSTNAME });
      expect(noCert.ok, `expected TLS-level rejection, got: ${noCert.statusLine}`).toBe(false);

      // Untrusted certificate: same TLS-level rejection.
      const wrongCA = await rawTLSProbe({ servername: MTLS_HOSTNAME, ...certPaths("wrong-ca") });
      expect(wrongCA.ok, `expected TLS-level rejection, got: ${wrongCA.statusLine}`).toBe(false);

      // The rejected connections never reach the authorize service: no
      // access/authorize log entries are produced for them.
      await sleep(2_000);
      const logs = pomerium.logs().join("\n");
      expect(logs).not.toMatch(/client-certificate-required|invalid-client-certificate/);
      expect(logs).not.toMatch(/"path":/);

      // A trusted certificate completes the handshake and gets a response.
      const valid = await rawTLSProbe({ servername: MTLS_HOSTNAME, ...certPaths("valid") });
      expect(valid.ok, valid.error).toBe(true);
      expect(valid.statusLine).toContain("200");
    } finally {
      await pomerium.stop();
    }
  });
});
