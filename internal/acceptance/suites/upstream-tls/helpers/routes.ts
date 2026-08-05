// Browser-driven route assertions: navigate as the logged-in user (the page is
// pre-authenticated via storageState) and assert on the response the browser
// receives. A 200 with the echo JSON means Pomerium completed the upstream
// handshake and proxied the request; a 503 means the upstream handshake failed
// (Envoy local reply, rendered as the branded error page in the browser).

import { expect, type Page } from "@playwright/test";
import { routeUrl, type RouteKey } from "../setup/constants.js";
import { gotoStable } from "./nav.js";

/** TLS facts reported by the Node echo upstream (mirrors upstream/server.js). */
export interface EchoTLS {
  protocol: string | null;
  cipher: string | null;
  /** SNI the upstream received (what Envoy sent). */
  servername: string | null;
  /** Whether the presented client certificate verified (mTLS upstream). */
  authorized: boolean;
  authorizationError: string | null;
  peerCertificate: {
    subject: Record<string, string> | null;
    issuer: Record<string, string> | null;
    subjectaltname: string | null;
  } | null;
}

/** Parsed response body from the Node echo upstream. */
export interface EchoJson {
  mode: string;
  method: string;
  path: string;
  tls: EchoTLS;
  /** Request headers matching x-pomerium-claim-* ONLY (server.js allowlist). */
  claims: Record<string, string>;
}

/**
 * Navigate (as the logged-in user) to a route fronting a Node echo upstream,
 * assert the page loaded (200 — Pomerium proxied), and return the echo JSON.
 * The first hit to a new route subdomain SSOs silently; page.goto follows the
 * redirect chain and resolves on the final response.
 */
export async function gotoEcho(page: Page, key: RouteKey, subpath = "/"): Promise<EchoJson> {
  const resp = await gotoStable(page, routeUrl(key) + subpath, { waitUntil: "domcontentloaded" });
  expect(resp, `${key}: navigation produced a response`).not.toBeNull();
  expect(resp!.status(), `${key} must load (200)`).toBe(200);
  // Response.json() reads the raw network body (independent of how Chromium
  // renders application/json), so this stays a genuine browser navigation.
  return (await resp!.json()) as EchoJson;
}

/**
 * Navigate to a route whose upstream handshake is expected to FAIL. Pomerium
 * serves an Envoy local reply; assert the browser receives HTTP 503.
 */
export async function expectHandshake503(page: Page, key: RouteKey, subpath = "/"): Promise<void> {
  const resp = await gotoStable(page, routeUrl(key) + subpath, { waitUntil: "domcontentloaded" });
  expect(resp, `${key}: navigation produced a response`).not.toBeNull();
  expect(resp!.status(), `${key} upstream handshake must fail with 503`).toBe(503);
}

/**
 * Navigate to the plain-HTTP control route's /json and return the identity
 * headers Pomerium injected (verify echoes only x-pomerium-claim-*).
 */
export async function verifyClaims(page: Page): Promise<Record<string, string>> {
  const resp = await gotoStable(page, `${routeUrl("control")}/json`, {
    waitUntil: "domcontentloaded",
  });
  expect(resp, "control /json produced a response").not.toBeNull();
  expect(resp!.status(), "control /json must reach the upstream").toBe(200);
  const data = (await resp!.json()) as { headers?: Record<string, unknown> };
  const headers: Record<string, string> = {};
  if (data.headers && typeof data.headers === "object") {
    for (const [key, value] of Object.entries(data.headers)) {
      headers[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
    }
  }
  return headers;
}
