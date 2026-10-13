// Fixed endpoints of the OIDC conformance e2e stack. Every hostname resolves to
// 127.0.0.1 on the host (public DNS for *.localhost.pomerium.io) and is a Docker
// network alias inside the stack, with identical ports on both sides.

export const KEYCLOAK_HOSTNAME = "keycloak.localhost.pomerium.io";

/** Pomerium's authenticate service: the issuer of the OIDC bridge. */
export const ISSUER = "https://authenticate.localhost.pomerium.io:8443";
export const DISCOVERY_URL = `${ISSUER}/.well-known/openid-configuration`;

/** Public base URL of the conformance suite (served through Pomerium). */
export const CONFORMANCE_BASE_URL = "https://conformance.localhost.pomerium.io:8443";

/**
 * Direct (non-Pomerium) URL of the conformance suite's REST API, published on a
 * host port. The runner talks to the API directly so the suite's long-poll
 * endpoints are not subject to Pomerium's route timeouts.
 */
export const CONFORMANCE_API_PORT = 18080;
export const CONFORMANCE_API_URL = `http://127.0.0.1:${CONFORMANCE_API_PORT}`;

/** Test alias: the suite serves the RP callback at /test/a/<alias>/callback. */
export const ALIAS = "pomerium";

/** Matches oidc_bridge.client_secret in pomerium/config.yaml. */
export const CLIENT_SECRET = "conformance-client-secret";

/**
 * OIDC bridge client IDs are URLs, and the client's one redirect URI is its
 * client_id URL exactly, so the client_id is the suite's callback URL.
 */
export const CLIENT_ID = `${CONFORMANCE_BASE_URL}/test/a/${ALIAS}/callback`;
