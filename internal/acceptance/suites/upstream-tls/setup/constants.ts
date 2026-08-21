// Fixed endpoints and paths of the container stack. Hostnames are
// *.localhost.pomerium.io (public DNS -> 127.0.0.1) and are ALSO registered as
// Docker network aliases; ports are fixed and identical on host and container,
// so these URLs are valid from the browser and from inside the containers alike.
//
// This suite exercises the connection between Pomerium and the service behind
// it (upstream TLS/mTLS via the per-route tls_* options), so the interesting
// endpoints are the *upstream* servers, reached in-network by alias.

import * as path from "node:path";
import { testUsers } from "../../shared/users.js";

export const AUTHENTICATE_URL = "https://authenticate.localhost.pomerium.io:8443";
export const AUTHENTICATE_HOSTNAME = new URL(AUTHENTICATE_URL).hostname;
export const KEYCLOAK_HOSTNAME = "keycloak.localhost.pomerium.io";
export const KEYCLOAK_REALM_URL = `http://${KEYCLOAK_HOSTNAME}:8080/realms/pomerium-e2e`;

/** Suite root and certificate output directories (see setup/certs.ts). */
export const SUITE_DIR = path.resolve(__dirname, "..");
export const CERTS_DIR = path.join(SUITE_DIR, ".certs");
export const UPSTREAM_CERTS_DIR = path.join(CERTS_DIR, "upstream");

// Saved browser session (Playwright storageState). The setup project logs in
// once and writes it here; the test project reuses it so every spec runs as an
// already-authenticated user (see playwright.config.ts + tests/auth.setup.ts).
export const AUTH_DIR = path.join(SUITE_DIR, ".auth");
export const STORAGE_STATE = path.join(AUTH_DIR, "user.json");

// --- Upstream servers (in-network aliases; no host ports) --------------------
// The pomerium/verify control upstream (plain HTTP) plus the first-party Node
// TLS/mTLS echo upstreams (one per handshake shape). The route `to` = these
// URLs; the alias doubles as the default SNI / verification name.
export const VERIFY_UPSTREAM_URL = "http://upstream:8000";
export const TLS_UPSTREAM_PORT = 4433;
export const TLS_UPSTREAM_HOST = "upstream-tls"; // plain server TLS
export const MTLS_UPSTREAM_HOST = "upstream-mtls"; // requires a client certificate
export const SNI_UPSTREAM_HOST = "upstream-sni"; // switches cert on SNI
export const RENEG_UPSTREAM_HOST = "upstream-reneg"; // server-initiated renegotiation
export const tlsUpstreamUrl = (host: string): string => `https://${host}:${TLS_UPSTREAM_PORT}`;

// SNI / verification names used by the server-name test cases. The SNI upstream
// serves server-sni-backend (SAN = SNI_BACKEND_NAME) only when the client sends
// that exact SNI, and its default (server-sni-decoy, SAN = SNI_DECOY_NAME)
// otherwise; SNI_BOGUS_NAME matches neither, so it never verifies.
export const SNI_BACKEND_NAME = "backend.internal.example.com";
export const SNI_DECOY_NAME = "decoy.invalid";
export const SNI_BOGUS_NAME = "bogus.invalid";

// One route host per test variant. Keys are used by the specs; values are the
// public *.localhost.pomerium.io names (127.0.0.1) that are ALSO Pomerium
// network aliases. All are single-label subdomains covered by the wildcard
// server certificate.
export const ROUTE_HOSTS = {
  control: "verify.localhost.pomerium.io",
  mtlsClaims: "mtls-claims.localhost.pomerium.io",
  customCa: "custom-ca.localhost.pomerium.io",
  customCaFile: "custom-ca-file.localhost.pomerium.io",
  customCaWrong: "custom-ca-wrong.localhost.pomerium.io",
  customCaNone: "custom-ca-none.localhost.pomerium.io",
  clientCert: "client-cert.localhost.pomerium.io",
  clientCertFile: "client-cert-file.localhost.pomerium.io",
  clientCertMissing: "client-cert-missing.localhost.pomerium.io",
  sniDefault: "sni-default.localhost.pomerium.io",
  sniServerName: "sni-server-name.localhost.pomerium.io",
  sniServerNameBogus: "sni-server-name-bogus.localhost.pomerium.io",
  sniUpstreamName: "sni-upstream-name.localhost.pomerium.io",
  sniUpstreamBogus: "sni-upstream-name-bogus.localhost.pomerium.io",
  sniPrecedence: "sni-precedence.localhost.pomerium.io",
  skipVerifyOff: "skip-verify-off.localhost.pomerium.io",
  skipVerifyOn: "skip-verify-on.localhost.pomerium.io",
  skipVerifyWins: "skip-verify-wins.localhost.pomerium.io",
  renegOff: "reneg-off.localhost.pomerium.io",
  renegOn: "reneg-on.localhost.pomerium.io",
} as const;

export type RouteKey = keyof typeof ROUTE_HOSTS;

export const ALL_ROUTE_HOSTNAMES: string[] = Object.values(ROUTE_HOSTS);

/** Public URL of a route (from the browser / APIRequestContext on the host). */
export function routeUrl(key: RouteKey): string {
  return `https://${ROUTE_HOSTS[key]}:8443`;
}

/**
 * Test user for the OIDC sign-in on the authenticated routes (control +
 * mtlsClaims), sourced from the shared realm fixture (../../shared/users).
 */
export const TEST_USER = testUsers.alice;
