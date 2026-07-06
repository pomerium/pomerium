// Non-browser HTTP client helpers built on Playwright's APIRequestContext.
//
// The manual QA plan's "choose a certificate" / "decline the certificate"
// browser prompts map to configuring (or not) a client certificate on the
// request context; "no IdP redirect" is asserted by disabling redirect
// following and inspecting the raw response.

import { expect, request, type APIRequestContext, type APIResponse } from "@playwright/test";
import { MTLS_URL } from "../setup/constants.js";
import { certPaths, type ClientCertType } from "./mtls.js";

/**
 * Create an APIRequestContext that presents the given client certificate
 * (or none, for the "declined certificate" case).
 */
export async function apiContext(
  certType: ClientCertType | null,
  originUrl: string = MTLS_URL,
): Promise<APIRequestContext> {
  return request.newContext({
    ignoreHTTPSErrors: true,
    ...(certType
      ? {
          clientCertificates: [
            { origin: new URL(originUrl).origin, ...certPaths(certType) },
          ],
        }
      : {}),
  });
}

/** Fetch without following redirects, so 30x responses stay observable. */
export async function getNoRedirect(ctx: APIRequestContext, url: string): Promise<APIResponse> {
  return ctx.get(url, { maxRedirects: 0 });
}

/**
 * Assert the mTLS denial contract: HTTP 495 with the client-certificate error
 * page, served immediately - no redirect toward the IdP / authenticate flow.
 */
export async function expectDenied495(
  ctx: APIRequestContext,
  url: string = MTLS_URL,
): Promise<APIResponse> {
  const res = await getNoRedirect(ctx, url);
  expect(res.status(), "mTLS denial must be HTTP 495").toBe(495);
  expect(await res.text()).toMatch(/client certificate/i);
  const location = res.headers()["location"] ?? "";
  expect(location, "495 must not redirect toward the IdP").not.toMatch(/authenticate|keycloak/);
  return res;
}

/** Assert the request passed Pomerium and reached the whoami upstream. */
export async function expectUpstreamReached(
  ctx: APIRequestContext,
  url: string = MTLS_URL,
): Promise<APIResponse> {
  const res = await ctx.get(url);
  expect(res.status(), "request must reach the upstream").toBe(200);
  expect(await res.text()).toContain("Hostname:"); // whoami body
  return res;
}

/** Poll a predicate over captured Pomerium logs (log writes are async). */
export async function waitForLogLine(
  logs: () => string[],
  match: RegExp,
  timeoutMs = 10_000,
): Promise<string> {
  const start = Date.now();
  for (;;) {
    const line = logs().find((l) => match.test(l));
    if (line) return line;
    if (Date.now() - start > timeoutMs) {
      throw new Error(`no log line matching ${match} within ${timeoutMs}ms`);
    }
    await new Promise((r) => setTimeout(r, 250));
  }
}
