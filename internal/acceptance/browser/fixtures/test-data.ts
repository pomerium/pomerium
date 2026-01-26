/**
 * Test data constants for E2E acceptance tests.
 * Defines URLs, timeouts, and other configuration values.
 */

/**
 * Base URLs for services in the test environment.
 */
export const urls = {
  /** Pomerium app route base URL */
  app: process.env.POMERIUM_URL || "https://app.localhost.pomerium.io:8443",

  /** Pomerium authenticate service URL */
  authenticate:
    process.env.AUTHENTICATE_URL || "https://authenticate.localhost.pomerium.io:8443",

  /** Pomerium admin route URL */
  admin: process.env.ADMIN_URL || "https://admin.localhost.pomerium.io:8443",

  /** Pomerium mTLS route URL (separate domain for mTLS testing) */
  mtls: process.env.MTLS_URL || "https://mtls.localhost.pomerium.io:8443",

  /** Keycloak IdP URL */
  keycloak: process.env.KEYCLOAK_URL || "http://keycloak.localhost.pomerium.io:8080",

  /** Cross-origin base used for CORS browser-context tests */
  corsOrigin: process.env.CORS_ORIGIN || "http://localhost:8081",
};

/**
 * Pomerium endpoint paths.
 */
export const paths = {
  /** OAuth2 callback endpoint */
  oauth2Callback: "/oauth2/callback",

  /** Sign in endpoint */
  signIn: "/.pomerium/sign_in",

  /** Sign out endpoint */
  signOut: "/.pomerium/sign_out",

  /** Signed out page */
  signedOut: "/.pomerium/signed_out",

  /** Device enrollment callback */
  deviceEnrolled: "/.pomerium/device-enrolled",

  /** Well-known Pomerium discovery */
  wellKnown: "/.well-known/pomerium",

  /** JWKS endpoint */
  jwks: "/.well-known/pomerium/jwks.json",

  /** HPKE public key endpoint */
  hpkePublicKey: "/.well-known/pomerium/hpke-public-key",

  /** Health check */
  healthz: "/healthz",

  /** Ping endpoint */
  ping: "/ping",

  /** User info endpoint */
  user: "/.pomerium/user",

  /** JWT endpoint */
  jwt: "/.pomerium/jwt",

  /** Pomerium routes portal (HTML) */
  routes: "/.pomerium/routes",

  /** Pomerium routes API (JSON) */
  routesApi: "/.pomerium/api/v1/routes",

  /** Programmatic login endpoint */
  apiLogin: "/.pomerium/api/v1/login",

  /** Pomerium dashboard root */
  dashboard: "/.pomerium/",

  /** WebAuthn endpoint */
  webAuthn: "/.pomerium/webauthn",
};

/**
 * Keycloak endpoint paths.
 */
export const keycloakPaths = {
  /** OIDC discovery */
  discovery: "/realms/pomerium-e2e/.well-known/openid-configuration",

  /** OIDC authorization endpoint */
  auth: "/realms/pomerium-e2e/protocol/openid-connect/auth",

  /** OIDC token endpoint */
  token: "/realms/pomerium-e2e/protocol/openid-connect/token",

  /** OIDC logout endpoint */
  logout: "/realms/pomerium-e2e/protocol/openid-connect/logout",

  /** Admin API base */
  adminApi: "/admin/realms/pomerium-e2e",
};

/**
 * Test route paths (relative to app URL).
 */
export const testRoutes = {
  /** Default authenticated route */
  default: "/",

  /** Route with email domain policy */
  byDomain: "/by-domain",

  /** Route with group policy */
  byGroup: "/by-group",

  /** Route with group + claim compound policy */
  byGroupClaim: "/by-group-claim",

  /** Route with explicit deny for bob@example.com */
  denyBob: "/deny-bob",

  /** Route allowing only admins */
  adminsOnly: "/admins-only",

  /** Route for JWT assertion testing */
  jwtTest: "/jwt-test",

  /** Route requiring both admins and engineering groups */
  engineeringAdmins: "/engineering-admins",
};

/**
 * WebSocket test routes (relative to app URL).
 */
export const wsRoutes = {
  /** WebSocket echo endpoint */
  echo: "/ws",

  /** WebSocket with preserve_host_header */
  preserveHost: "/ws-preserve-host",
};

/**
 * CORS test routes (relative to app URL).
 */
export const corsRoutes = {
  /** Route with cors_allow_preflight enabled */
  enabled: "/cors-enabled",

  /** Route without cors_allow_preflight */
  disabled: "/cors-disabled",

  /** Public route with CORS enabled */
  public: "/cors-public",
};

/**
 * mTLS URL. For detailed mTLS helpers, import from helpers/mtls.ts.
 */
export const mtlsUrlConfig = {
  /** mTLS domain - accepts certs from root and intermediate CA */
  mtls: process.env.MTLS_URL || "https://mtls.localhost.pomerium.io:8443",
};

/**
 * Cookie names used by Pomerium.
 */
export const cookieNames = {
  /** Session cookie (default name) */
  session: "_pomerium",

  /** CSRF cookie */
  csrf: "_pomerium_csrf",
};

/**
 * Timeouts for various operations (in milliseconds).
 */
export const timeouts = {
  /** Short timeout for quick operations */
  short: 5000,

  /** Medium timeout for standard operations */
  medium: 10000,

  /** Long timeout for auth flows */
  long: 30000,

  /** Extra long timeout for complex flows */
  extraLong: 60000,

  /** Access token lifespan in Keycloak (5 seconds) */
  accessTokenLifespan: 5000,

  /** SSO session idle timeout in Keycloak (30 seconds) */
  ssoSessionIdle: 30000,

  /** SSO session max lifespan in Keycloak (2 minutes) */
  ssoSessionMax: 120000,

  /** Buffer time to wait after token expiry */
  tokenExpiryBuffer: 2000,

  /** Poll interval for waiting operations */
  pollInterval: 500,
};

/**
 * Expected HTTP status codes.
 */
export const httpStatus = {
  ok: 200,
  redirect: 302,
  forbidden: 403,
  unauthorized: 401,
  notFound: 404,
};

/**
 * Expected header names in upstream responses.
 */
export const headerNames = {
  /** Pomerium JWT assertion header */
  jwtAssertion: "x-pomerium-jwt-assertion",

  /** Email claim header */
  claimEmail: "x-pomerium-claim-email",

  /** Groups claim header */
  claimGroups: "x-pomerium-claim-groups",

  /** User claim header */
  claimUser: "x-pomerium-claim-user",
};

/**
 * Build a full URL from base and path.
 */
export function buildUrl(base: string, path: string): string {
  const baseUrl = base.endsWith("/") ? base.slice(0, -1) : base;
  const pathPart = path.startsWith("/") ? path : `/${path}`;
  return `${baseUrl}${pathPart}`;
}

/**
 * Get the full app URL for a test route.
 */
export function getAppUrl(route: string): string {
  return buildUrl(urls.app, route);
}

/**
 * Get the full authenticate URL for a path.
 */
export function getAuthenticateUrl(path: string): string {
  return buildUrl(urls.authenticate, path);
}

/**
 * Get the full Keycloak URL for a path.
 */
export function getKeycloakUrl(path: string): string {
  return buildUrl(urls.keycloak, path);
}
