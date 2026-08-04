/**
 * Group G - identity propagation: certificate-derived request headers.
 * Test plan: Client Certificates (mTLS), TC-CC-17..18.
 *
 * Supported substitution variables (authorize/evaluator/
 * headers_evaluator_evaluation.go): pomerium.client_cert_fingerprint,
 * pomerium.client_cert_san_dns, pomerium.client_cert_san_email.
 * (No ip/uri SAN variables exist - resolved plan open question #5.)
 *
 * client-valid carries SAN DNS alice.company.com AND email alice@company.com,
 * and its fingerprint is recorded at generation time, so all three headers
 * are assertable against known values. Routes are public so the assertions
 * isolate the certificate-derived headers (no login).
 *
 * The injected headers are named X-Pomerium-Claim-* because the upstream
 * (pomerium/verify) only echoes headers whose name contains "x-pomerium-claim"
 * in its /json output. The $pomerium.client_cert_* substitution being tested
 * is identical regardless of the header name.
 */

import { test, expect } from "@playwright/test";
import { fetchVerifyJson, withCert } from "../helpers/api.js";
import { fingerprint } from "../helpers/fixtures.js";
import { startPomerium } from "../setup/containers.js";
import { CONTAINER_CERTS, generateConfig } from "../setup/pomerium-config.js";
import { MTLS_URL } from "../setup/constants.js";

test.describe("Group G: certificate-derived request headers", () => {
  test("TC-CC-17: static fingerprint request header", async () => {
    const pomerium = await startPomerium({
      configFile: generateConfig({
        name: "headers-fingerprint",
        downstreamMtls: { ca_file: CONTAINER_CERTS.rootCA },
        route: {
          publicAccess: true,
          setRequestHeaders: {
            "X-Pomerium-Claim-Cert-Fingerprint": "$pomerium.client_cert_fingerprint",
          },
        },
      }),
    });
    try {
      await withCert("valid", async (ctx) => {
        const { headers } = await fetchVerifyJson(ctx, MTLS_URL);
        const value = headers["x-pomerium-claim-cert-fingerprint"];
        expect(value, "upstream must receive the fingerprint header").toBeTruthy();
        expect(value.toLowerCase()).toContain(fingerprint("valid"));
      });
    } finally {
      await pomerium.stop();
    }
  });

  test("TC-CC-18: dynamic request headers (fingerprint + SAN DNS + SAN email)", async () => {
    const pomerium = await startPomerium({
      configFile: generateConfig({
        name: "headers-dynamic",
        downstreamMtls: { ca_file: CONTAINER_CERTS.rootCA },
        route: {
          publicAccess: true,
          setRequestHeaders: {
            "X-Pomerium-Claim-Cert-Fingerprint": "$pomerium.client_cert_fingerprint",
            "X-Pomerium-Claim-Cert-San-Dns": "${pomerium.client_cert_san_dns}",
            "X-Pomerium-Claim-Cert-San-Email": "${pomerium.client_cert_san_email}",
          },
        },
      }),
    });
    try {
      await withCert("valid", async (ctx) => {
        // The route is public and reaches the backend; verify's /json echoes
        // the certificate-derived values in the injected headers.
        const { headers } = await fetchVerifyJson(ctx, MTLS_URL);
        expect(headers["x-pomerium-claim-cert-fingerprint"]?.toLowerCase()).toContain(
          fingerprint("valid"),
        );
        expect(headers["x-pomerium-claim-cert-san-dns"]).toContain("alice.company.com");
        expect(headers["x-pomerium-claim-cert-san-email"]).toContain("alice@company.com");
      });
    } finally {
      await pomerium.stop();
    }
  });
});
