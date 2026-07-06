// Fixed endpoints of the container stack. Hostnames are *.localhost.pomerium.io
// (public DNS -> 127.0.0.1) and are ALSO registered as Docker network aliases;
// ports are fixed and identical on host and container, so these URLs are valid
// from the browser and from inside the containers alike.

export const MTLS_URL = "https://mtls.localhost.pomerium.io:8443";
export const AUTHENTICATE_URL = "https://authenticate.localhost.pomerium.io:8443";
export const KEYCLOAK_HOSTNAME = "keycloak.localhost.pomerium.io";

/** Test user from the shared acceptance realm (../keycloak). The mTLS client
 * certificates are issued to the same identity (SAN email alice@company.com). */
export const TEST_USER = {
  email: "alice@company.com",
  password: "password123",
};
