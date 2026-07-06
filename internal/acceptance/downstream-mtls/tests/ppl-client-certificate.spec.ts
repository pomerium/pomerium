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
import { newContextWithCert } from "../helpers/mtls.js";
import type { ClientCertType } from "../helpers/mtls.js";
import { waitForKeycloakLoginPage, submitLoginForm } from "../helpers/login.js";
import { fingerprint, spkiHash } from "../helpers/fixtures.js";
import { startPomerium, type StartedPomerium } from "../setup/containers.js";
import { generateConfig, CONTAINER_CERTS } from "../setup/pomerium-config.js";
import { MTLS_URL, TEST_USER } from "../setup/constants.js";

const mtlsHostname = new URL(MTLS_URL).hostname;

/** Sign in through Keycloak with the given client certificate, then return
 * the status of a fresh navigation to the mTLS route. */
async function loginAndGetStatus(browser: Browser, cert: ClientCertType): Promise<number> {
  const context = await newContextWithCert(browser, cert, MTLS_URL);
  try {
    const page = await context.newPage();
    await page.goto(MTLS_URL, { waitUntil: "domcontentloaded" });
    await waitForKeycloakLoginPage(page);
    await submitLoginForm(page, TEST_USER.email, TEST_USER.password);
    await page.waitForURL((url) => url.hostname === mtlsHostname);
    const response = await page.goto(MTLS_URL, { waitUntil: "domcontentloaded" });
    return response!.status();
  } finally {
    await context.close();
  }
}

function policyRoute(clientCertificate: Record<string, unknown>): unknown[] {
  return [
    {
      from: MTLS_URL,
      to: "http://upstream:80",
      pass_identity_headers: true,
      policy: [
        {
          allow: {
            and: [{ authenticated_user: true }, { client_certificate: clientCertificate }],
          },
        },
      ],
    },
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
