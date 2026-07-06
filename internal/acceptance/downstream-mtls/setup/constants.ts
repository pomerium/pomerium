// Fixed endpoints and paths of the container stack. Hostnames are
// *.localhost.pomerium.io (public DNS -> 127.0.0.1) and are ALSO registered as
// Docker network aliases; ports are fixed and identical on host and container,
// so these URLs are valid from the browser and from inside the containers alike.

import * as path from "node:path";

export const MTLS_URL = "https://mtls.localhost.pomerium.io:8443";
export const AUTHENTICATE_URL = "https://authenticate.localhost.pomerium.io:8443";
export const KEYCLOAK_HOSTNAME = "keycloak.localhost.pomerium.io";
export const KEYCLOAK_REALM_URL = `http://${KEYCLOAK_HOSTNAME}:8080/realms/pomerium-e2e`;

export const MTLS_HOSTNAME = new URL(MTLS_URL).hostname;
export const AUTHENTICATE_HOSTNAME = new URL(AUTHENTICATE_URL).hostname;

/** In-container URL of the whoami upstream ("upstream" is a network alias). */
export const UPSTREAM_URL = "http://upstream:80";

/** Suite root and certificate output directories (see setup/certs.ts). */
export const SUITE_DIR = path.resolve(__dirname, "..");
export const CERTS_DIR = path.join(SUITE_DIR, ".certs");
export const MTLS_CERTS_DIR = path.join(CERTS_DIR, "mtls");

/** Test user from the shared acceptance realm (../keycloak). The mTLS client
 * certificates are issued to the same identity (SAN email alice@company.com). */
export const TEST_USER = {
  email: "alice@company.com",
  password: "password123",
};
