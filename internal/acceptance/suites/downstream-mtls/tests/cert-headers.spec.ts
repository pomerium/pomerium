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
 */

import { test, expect } from "@playwright/test";
import { withCert } from "../helpers/api.js";
import { fingerprint } from "../helpers/fixtures.js";
import { startPomerium } from "../setup/containers.js";
import { CONTAINER_CERTS, generateConfig } from "../setup/pomerium-config.js";
import { MTLS_URL } from "../setup/constants.js";

function headerLine(body: string, name: string): string | undefined {
  return body.split("\n").find((l) => l.toLowerCase().startsWith(`${name.toLowerCase()}:`));
}

test.describe("Group G: certificate-derived request headers", () => {
  test("TC-CC-17: static fingerprint request header", async () => {
    const pomerium = await startPomerium({
      configFile: generateConfig({
        name: "headers-fingerprint",
        downstreamMtls: { ca_file: CONTAINER_CERTS.rootCA },
        route: {
          publicAccess: true,
          setRequestHeaders: { "X-Client-Cert": "$pomerium.client_cert_fingerprint" },
        },
      }),
    });
    try {
      await withCert("valid", async (ctx) => {
        const res = await ctx.get(MTLS_URL);
        expect(res.status()).toBe(200);
        const body = await res.text(); // whoami echoes the request headers
        const line = headerLine(body, "X-Client-Cert");
        expect(line, "upstream must receive X-Client-Cert").toBeTruthy();
        expect(line!.toLowerCase()).toContain(fingerprint("valid"));
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
            "X-Client-Cert-Fingerprint": "$pomerium.client_cert_fingerprint",
            "X-Client-Cert-San-Dns": "${pomerium.client_cert_san_dns}",
            "X-Client-Cert-San-Email": "${pomerium.client_cert_san_email}",
          },
        },
      }),
    });
    try {
      await withCert("valid", async (ctx) => {
        // Request to the route root is allowed and reaches the backend...
        const res = await ctx.get(MTLS_URL);
        expect(res.status()).toBe(200);
        // ...and the echoed headers carry the certificate-derived values.
        const body = await res.text();
        expect(headerLine(body, "X-Client-Cert-Fingerprint")?.toLowerCase()).toContain(
          fingerprint("valid"),
        );
        expect(headerLine(body, "X-Client-Cert-San-Dns")).toContain("alice.company.com");
        expect(headerLine(body, "X-Client-Cert-San-Email")).toContain("alice@company.com");
      });
    } finally {
      await pomerium.stop();
    }
  });
});
