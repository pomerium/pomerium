// Pomerium configuration generator for per-test-group variants.
//
// Most test cases need their own downstream_mtls configuration (enforcement
// modes, CA surfaces, CRL, SAN matchers, verify depth, per-route policies), so
// configs are generated at runtime into .gen/ (gitignored) and bind-mounted
// into the Pomerium container by startPomerium. Files are written as JSON,
// which is valid YAML - no YAML dependency needed.
//
// The defaults produce the suite's base configuration: trust root is the ROOT
// CA only (not ca-chain.crt), so chain-depth behavior stays testable via
// max_verify_depth; enforcement stays at policy_with_default_deny (handshake
// accepts any certificate, requests without a valid one get HTTP 495).

import { mkdirSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import { AUTHENTICATE_URL, KEYCLOAK_REALM_URL, MTLS_URL, SUITE_DIR, UPSTREAM_URL } from "./constants.js";

const GEN_DIR = path.join(SUITE_DIR, ".gen");

/** In-container paths of the mounted certificate material (see certs.ts). */
export const CONTAINER_CERTS = {
  serverCert: "/certs/pomerium.crt",
  serverKey: "/certs/pomerium.key",
  rootCA: "/certs/mtls/root-ca.crt",
  caChain: "/certs/mtls/ca-chain.crt",
  crlRoot: "/certs/mtls/crl-root.pem",
  crlChain: "/certs/mtls/crl-chain.pem",
} as const;

export interface RouteOptions {
  /** Path prefix (for multiple routes on the same host). */
  prefix?: string;
  /** PPL policy blocks. Ignored when publicAccess is set. */
  policy?: unknown[];
  /** Use allow_public_unauthenticated_access instead of a policy. */
  publicAccess?: boolean;
  setRequestHeaders?: Record<string, string>;
}

export interface PomeriumConfigOptions {
  /** File name stem for the generated config (use the test group name). */
  name: string;
  /**
   * The downstream_mtls block. Defaults to { ca_file: rootCA }.
   * Pass null to OMIT the block entirely (mTLS disabled).
   */
  downstreamMtls?: Record<string, unknown> | null;
  /** Full routes override; defaults to a single route built from `route`. */
  routes?: unknown[];
  route?: RouteOptions;
  /** Extra top-level settings merged last. */
  extra?: Record<string, unknown>;
}

export function buildRoute(opts: RouteOptions = {}): Record<string, unknown> {
  const route: Record<string, unknown> = {
    from: MTLS_URL,
    to: UPSTREAM_URL,
  };
  if (opts.prefix) route.prefix = opts.prefix;
  route.pass_identity_headers = true;
  if (opts.setRequestHeaders) route.set_request_headers = opts.setRequestHeaders;
  if (opts.publicAccess) {
    route.allow_public_unauthenticated_access = true;
  } else {
    route.policy = opts.policy ?? [{ allow: { or: [{ authenticated_user: true }] } }];
  }
  return route;
}

/** Write a config variant into .gen/ and return its host path. */
export function generateConfig(opts: PomeriumConfigOptions): string {
  const config: Record<string, unknown> = {
    address: ":8443",
    authenticate_service_url: AUTHENTICATE_URL,
    idp_provider: "oidc",
    idp_provider_url: KEYCLOAK_REALM_URL,
    idp_client_id: "pomerium",
    idp_client_secret: "pomerium-e2e-secret",
    idp_scopes: ["openid", "profile", "email", "groups", "offline_access"],
    certificate_file: CONTAINER_CERTS.serverCert,
    certificate_key_file: CONTAINER_CERTS.serverKey,
    // Test-only secrets (reproducible tests) - NEVER use them in production.
    cookie_secret: "dj5y7E03ULP9YebCgHNIXmxWnWfYlVXCgwbm9IEdysI=",
    shared_secret: "0CdEkgO02jgxmgSC2AdkqIbFELAN4CGw0v0RY85xNr4=",
    log_level: "debug",
    jwt_claims_headers: { "X-Pomerium-Claim-Email": "email" },
  };

  if (opts.downstreamMtls !== null) {
    config.downstream_mtls = opts.downstreamMtls ?? { ca_file: CONTAINER_CERTS.rootCA };
  }
  config.routes = opts.routes ?? [buildRoute(opts.route)];
  Object.assign(config, opts.extra);

  mkdirSync(GEN_DIR, { recursive: true });
  const file = path.join(GEN_DIR, `${opts.name}.yaml`);
  writeFileSync(file, JSON.stringify(config, null, 2));
  return file;
}

/** The suite's base configuration: root-CA trust, one auth-requiring route. */
export function baseConfigFile(): string {
  return generateConfig({ name: "base" });
}
