// Primitives for the browser-driven route tests. Specs navigate as the
// logged-in user (the page is pre-authenticated via storageState) inside
// explicit test.step blocks and assert on what the browser receives: a 200
// with the echo JSON means Pomerium completed the upstream TLS handshake and
// proxied the request; a 503 means the handshake failed and Pomerium served
// the branded upstream error page (an Envoy local reply) with Envoy's own
// diagnostics embedded in window.POMERIUM_DATA
// (config/envoyconfig/local_reply.go).

import type { Page, Response } from "@playwright/test";
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
  /**
   * True only when a server-initiated renegotiation completed before this
   * response (reneg mode, GET /reneg) - guards the allow-renegotiation
   * positive case against a quiet 200 that never renegotiated.
   */
  renegotiated: boolean;
  tls: EchoTLS;
  /** Request headers matching x-pomerium-claim-* ONLY (server.js allowlist). */
  claims: Record<string, string>;
}

/**
 * Navigate (as the logged-in user) to a route and return the final response
 * for the spec's steps to assert on. page.goto follows the redirect chain, so
 * the first hit to a new route subdomain SSOs silently; every navigation goes
 * through gotoStable (ERR_NETWORK_CHANGED retry).
 */
export function openRoute(page: Page, key: RouteKey, subpath = "/"): Promise<Response | null> {
  return gotoStable(page, routeUrl(key) + subpath, { waitUntil: "domcontentloaded" });
}

/**
 * Diagnostics Envoy embeds in the branded error page (window.POMERIUM_DATA).
 * All values are strings Envoy substituted into the rendered HTML
 * (config/envoyconfig/local_reply.go). The React app mutates `page` in that
 * object client-side - never assert on it.
 */
export interface PomeriumErrorData {
  status?: string;
  /** Envoy %RESPONSE_CODE_DETAILS%, e.g. upstream_reset_before_response_started{...}. */
  statusText?: string;
  requestId?: string;
  /** Envoy %RESPONSE_FLAGS%, e.g. UF (UpstreamConnectionFailure). */
  responseFlags?: string;
}

/**
 * Read window.POMERIUM_DATA from the rendered error page. The data is set by
 * an inline script that runs during parse, so it is present by
 * domcontentloaded. (globalThis: the suite tsconfig has no DOM lib.)
 */
export async function pomeriumErrorData(page: Page): Promise<PomeriumErrorData | undefined> {
  return (await page.evaluate(
    () => (globalThis as { POMERIUM_DATA?: unknown }).POMERIUM_DATA,
  )) as PomeriumErrorData | undefined;
}

/**
 * Expected user-visible outcome of an upstream 503 local reply: statusText =
 * Envoy %RESPONSE_CODE_DETAILS%, responseFlags = Envoy %RESPONSE_FLAGS% (both
 * read from window.POMERIUM_DATA), pageText = copy the rendered error page
 * must show. Structural tokens only (no OpenSSL error codes), so envoy
 * upgrades in the pomerium/pomerium:main image don't break the suite. The
 * values below were pinned from an actual run; see the README behavior
 * gotchas for the observed strings.
 */
export interface UpstreamErrorExpectations {
  statusText: RegExp;
  responseFlags: RegExp;
  pageText: RegExp;
}

/**
 * The upstream's cert chain can't be verified (untrusted / unrelated CA): the
 * handshake fails with a TLS_error detail (flag UF =
 * UpstreamConnectionFailure). BoringSSL's detail ends in
 * "unable_to_get_local_issuer_certificate", and that "local" substring makes
 * the UI's error-page heuristic (ui/src/App.tsx picks the upstream page only
 * when statusText contains "upstream" and NOT "local") fall back to the
 * GENERIC error page instead of "Web Server is down" - so assert the
 * invariant both page variants render: the Envoy failure detail is shown to
 * the user.
 */
export const TLS_UNTRUSTED_CA: UpstreamErrorExpectations = {
  statusText: /^upstream_reset_before_response_started\{(remote_)?connection_failure\|TLS_error/,
  responseFlags: /^UF$/,
  pageText: /upstream_reset_before_response_started/,
};

/**
 * The chain verifies but the verification name is not on the served cert's
 * SAN: Envoy's SAN matcher rejects the handshake (flag UF) with a detail
 * naming the SAN matcher, and the branded "Web Server is down" upstream error
 * page renders.
 */
export const TLS_SAN_MISMATCH: UpstreamErrorExpectations = {
  statusText:
    /^upstream_reset_before_response_started\{(remote_)?connection_failure\|TLS_error.*SAN_matcher/,
  responseFlags: /^UF$/,
  pageText: /web server is down/i,
};

/**
 * An ESTABLISHED upstream connection is dropped instead of the handshake
 * failing: an mTLS upstream requiring a client cert under TLS 1.3 (its
 * certificate_required alert arrives after the client considers the handshake
 * complete) or Envoy refusing a server-initiated renegotiation. Plain
 * connection_termination with no TLS_error detail (flag UC =
 * UpstreamConnectionTermination); the "Web Server is down" page renders.
 */
export const UPSTREAM_TERMINATED: UpstreamErrorExpectations = {
  statusText: /^upstream_reset_before_response_started\{connection_termination/,
  responseFlags: /^UC$/,
  pageText: /web server is down/i,
};
