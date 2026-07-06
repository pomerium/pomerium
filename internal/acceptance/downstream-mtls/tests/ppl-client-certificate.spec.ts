/**
 * Group H - PPL `client_certificate` policy criterion.
 * Test plan: Client Certificates (mTLS), TC-CC-19..20.
 *
 * These policies combine authenticated_user with client_certificate, so the
 * specs run the REAL browser sign-in (Keycloak) with the client certificate
 * attached to the browser context. A trusted-but-unlisted certificate passes
 * the mTLS layer and the login, then fails the allow rule: HTTP 403 (not 495).
 */

import { test, expect, type Browser } from "@playwright/test";
import { newContextWithCert, type ClientCertType } from "../helpers/mtls.js";
import { signInOnMtlsRoute } from "../helpers/login.js";
import { fingerprint, spkiHash } from "../helpers/fixtures.js";
import { startPomerium, type StartedPomerium } from "../setup/containers.js";
import { buildRoute, generateConfig, CONTAINER_CERTS } from "../setup/pomerium-config.js";
import { MTLS_URL } from "../setup/constants.js";

/** Sign in through Keycloak with the given client certificate, then return
 * the status of a fresh navigation to the mTLS route. */
async function loginAndGetStatus(browser: Browser, cert: ClientCertType): Promise<number> {
  const context = await newContextWithCert(browser, cert, MTLS_URL);
  try {
    const page = await context.newPage();
    await signInOnMtlsRoute(page);
    const response = await page.goto(MTLS_URL, { waitUntil: "domcontentloaded" });
    return response!.status();
  } finally {
    await context.close();
  }
}

function policyRoute(clientCertificate: Record<string, unknown>): unknown[] {
  return [
    buildRoute({
      policy: [
        {
          allow: {
            and: [{ authenticated_user: true }, { client_certificate: clientCertificate }],
          },
        },
      ],
    }),
  ];
}

test.describe("Group H: PPL client_certificate criterion", () => {
  test("TC-CC-19: allow by fingerprint list", async ({ browser }) => {
    const pomerium: StartedPomerium = await startPomerium({
      configFile: generateConfig({
        name: "ppl-fingerprint-list",
        downstreamMtls: { ca_file: CONTAINER_CERTS.rootCA },
        routes: policyRoute({
          fingerprint: [fingerprint("valid"), fingerprint("san-dns")],
        }),
      }),
    });
    try {
      // Certificates whose fingerprints are in the list are allowed.
      expect(await loginAndGetStatus(browser, "valid")).toBe(200);
      expect(await loginAndGetStatus(browser, "san-dns")).toBe(200);
      // A trusted, valid certificate NOT in the list is denied by policy.
      expect(await loginAndGetStatus(browser, "san-email")).toBe(403);
    } finally {
      await pomerium.stop();
    }
  });

  test("TC-CC-20: allow by fingerprint + SPKI hash", async ({ browser }) => {
    const pomerium: StartedPomerium = await startPomerium({
      configFile: generateConfig({
        name: "ppl-fingerprint-spki",
        downstreamMtls: { ca_file: CONTAINER_CERTS.rootCA },
        routes: policyRoute({
          fingerprint: fingerprint("valid"),
          spki_hash: spkiHash("valid"),
        }),
      }),
    });
    try {
      // The certificate matching both the fingerprint and the SPKI hash.
      expect(await loginAndGetStatus(browser, "valid")).toBe(200);
      // A trusted certificate with a different key/fingerprint is denied.
      expect(await loginAndGetStatus(browser, "san-dns")).toBe(403);
    } finally {
      await pomerium.stop();
    }
  });
});
