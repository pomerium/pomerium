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
export async function apiContext(certType: ClientCertType | null): Promise<APIRequestContext> {
  return request.newContext({
    ignoreHTTPSErrors: true,
    ...(certType
      ? {
          clientCertificates: [
            { origin: new URL(MTLS_URL).origin, ...certPaths(certType) },
          ],
        }
      : {}),
  });
}

/** Run `fn` with a request context presenting the given certificate, then dispose it. */
export async function withCert<T>(
  certType: ClientCertType | null,
  fn: (ctx: APIRequestContext) => Promise<T>,
): Promise<T> {
  const ctx = await apiContext(certType);
  try {
    return await fn(ctx);
  } finally {
    await ctx.dispose();
  }
}

/** Fetch without following redirects, so 30x responses stay observable. */
export async function getNoRedirect(ctx: APIRequestContext, url: string): Promise<APIResponse> {
  return ctx.get(url, { maxRedirects: 0 });
}

/**
 * Parsed pomerium/verify /json response. `headers` carries ONLY the request
 * headers whose name contains "x-pomerium-claim" (verify filters the rest);
 * names are lowercased and multi-value headers are joined with ", ".
 */
export interface VerifyJson {
  headers: Record<string, string>;
  request?: Record<string, unknown>;
  identity?: unknown;
  error?: unknown;
}

/**
 * Fetch verify's /json for `url` and return it normalized. Asserts HTTP 200 -
 * the request reached the upstream (see expectUpstreamReached for the marker).
 */
export async function fetchVerifyJson(
  ctx: APIRequestContext,
  url: string = MTLS_URL,
): Promise<VerifyJson> {
  const res = await ctx.get(`${url}/json`);
  expect(res.status(), "verify /json must reach the upstream").toBe(200);
  const data = (await res.json()) as Record<string, unknown>;

  const headers: Record<string, string> = {};
  const rawHeaders = data.headers;
  if (typeof rawHeaders === "object" && rawHeaders !== null) {
    for (const [key, value] of Object.entries(rawHeaders)) {
      headers[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
    }
  }

  return {
    headers,
    request: (data.request ?? undefined) as Record<string, unknown> | undefined,
    identity: data.identity,
    error: data.error,
  };
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

/** Assert the request passed Pomerium and reached the pomerium/verify upstream. */
export async function expectUpstreamReached(
  ctx: APIRequestContext,
  url: string = MTLS_URL,
): Promise<VerifyJson> {
  const json = await fetchVerifyJson(ctx, url);
  expect(json.request, "verify must report the proxied request").toBeTruthy();
  return json;
}

/** Assert the request entered the normal login flow (302 toward the IdP). */
export async function expectLoginRedirect(
  ctx: APIRequestContext,
  url: string = MTLS_URL,
): Promise<APIResponse> {
  const res = await getNoRedirect(ctx, url);
  expect(res.status(), "request must enter the login flow").toBe(302);
  expect(res.headers()["location"] ?? "").toMatch(
    /authenticate\.localhost\.pomerium\.io|\.pomerium\/sign_in/,
  );
  return res;
}

/** Poll a predicate over captured Pomerium logs (log writes are async). */
export async function waitForLogLine(
  logs: () => string[],
  match: RegExp,
  timeoutMs = 10_000,
): Promise<void> {
  await expect
    .poll(() => logs().some((l) => match.test(l)), {
      message: `no log line matching ${match}`,
      timeout: timeoutMs,
    })
    .toBe(true);
}
