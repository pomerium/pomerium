// Fixed endpoints and paths of the container stack. Hostnames are
// *.localhost.pomerium.io (public DNS -> 127.0.0.1) and are ALSO registered as
// Docker network aliases; ports are fixed and identical on host and container,
// so these URLs are valid from the browser and from inside the containers alike.
//
// The protected route host is verify.localhost.pomerium.io, mirroring the base
// config.yaml of the QA test plans this suite automates (Core.Logging,
// Core.Metrics, Core.OTEL Tracing).

import * as path from "node:path";
import { testUsers } from "../../shared/users.js";

export const VERIFY_URL = "https://verify.localhost.pomerium.io:8443";
export const AUTHENTICATE_URL = "https://authenticate.localhost.pomerium.io:8443";
export const KEYCLOAK_HOSTNAME = "keycloak.localhost.pomerium.io";
export const KEYCLOAK_REALM_URL = `http://${KEYCLOAK_HOSTNAME}:8080/realms/pomerium-e2e`;

export const VERIFY_HOSTNAME = new URL(VERIFY_URL).hostname;
export const AUTHENTICATE_HOSTNAME = new URL(AUTHENTICATE_URL).hostname;

/** In-container URL of the pomerium/verify upstream ("upstream" is a network alias). */
export const UPSTREAM_URL = "http://upstream:8000";

/**
 * Jaeger collector. Pomerium exports OTLP to the in-network alias; the tests
 * read spans back through the query API on the fixed host port.
 */
export const JAEGER_ALIAS = "jaeger";
export const JAEGER_OTLP_HTTP_URL = `http://${JAEGER_ALIAS}:4318`;
export const JAEGER_QUERY_PORT = 16686;
export const JAEGER_QUERY_URL = `http://127.0.0.1:${JAEGER_QUERY_PORT}`;

/**
 * Pomerium's metrics listener (metrics_address). The port is always published
 * by startPomerium; whether anything listens on it is decided by the config
 * variant under test.
 */
export const METRICS_PORT = 9902;
export const METRICS_URL = `http://127.0.0.1:${METRICS_PORT}`;

/** Suite root and certificate output directory (see setup/certs.ts). */
export const SUITE_DIR = path.resolve(__dirname, "..");
export const CERTS_DIR = path.join(SUITE_DIR, ".certs");

/** Test user for authenticated routes, sourced from the shared realm fixture. */
export const TEST_USER = testUsers.alice;

/** Env var carrying the shared network name from global setup to the workers. */
export const NETWORK_ENV = "OBS_E2E_NETWORK";
