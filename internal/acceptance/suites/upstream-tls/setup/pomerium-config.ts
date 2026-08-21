// Pomerium configuration generator for the upstream TLS/mTLS suite.
//
// Every route's upstream-TLS behavior is driven by its per-route tls_* options,
// so one config with a route per test variant covers all runtime cases - the
// specs share it (mainConfigFile) and select behavior by route host. Configs
// are written as JSON (valid YAML) into .gen/ (gitignored) and bind-mounted
// into the Pomerium container by startPomerium. The config-validation spec
// generates minimal single-route configs of its own (deliberately invalid).
//
// NOTE: functions that read generated cert material (mainRoutes, the base64
// helpers) must be called at test time (beforeAll / test body), never at module
// scope, because the PKI is produced in global setup.

import { mkdirSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import {
  upstreamCABase64,
  wrongCABase64,
  clientCertBase64,
  clientKeyBase64,
} from "../helpers/fixtures.js";
import {
  AUTHENTICATE_URL,
  KEYCLOAK_REALM_URL,
  MTLS_UPSTREAM_HOST,
  RENEG_UPSTREAM_HOST,
  ROUTE_HOSTS,
  SNI_BACKEND_NAME,
  SNI_BOGUS_NAME,
  SNI_UPSTREAM_HOST,
  SUITE_DIR,
  TLS_UPSTREAM_HOST,
  VERIFY_UPSTREAM_URL,
  tlsUpstreamUrl,
} from "./constants.js";

const GEN_DIR = path.join(SUITE_DIR, ".gen");

/** In-container paths of the mounted certificate material (see scripts/gen-certs.sh). */
export const CONTAINER_CERTS = {
  serverCert: "/certs/pomerium.crt",
  serverKey: "/certs/pomerium.key",
  upstreamCA: "/certs/upstream/upstream-ca.crt",
  wrongCA: "/certs/upstream/wrong-ca.crt",
  clientCert: "/certs/upstream/pomerium-client.crt",
  clientKey: "/certs/upstream/pomerium-client.key",
  mismatchedKey: "/certs/upstream/mismatched.key",
  /** A path that intentionally does not exist (missing-file config error). */
  missingFile: "/certs/upstream/does-not-exist.crt",
} as const;

/** Per-route upstream TLS options; each field maps 1:1 to a tls_* config key. */
export interface UpstreamTLS {
  customCA?: string; // tls_custom_ca (base64 PEM)
  customCAFile?: string; // tls_custom_ca_file (container path)
  clientCert?: string; // tls_client_cert (base64 PEM)
  clientKey?: string; // tls_client_key (base64 PEM)
  clientCertFile?: string; // tls_client_cert_file (container path)
  clientKeyFile?: string; // tls_client_key_file (container path)
  serverName?: string; // tls_server_name (deprecated key)
  upstreamServerName?: string; // tls_upstream_server_name (takes precedence)
  skipVerify?: boolean; // tls_skip_verify
  allowRenegotiation?: boolean; // tls_upstream_allow_renegotiation
}

export interface RouteSpec {
  /** Route host (the `from` is https://<host>:8443). */
  host: string;
  /** Upstream URL (the `to`). */
  to: string;
  tls?: UpstreamTLS;
  /** Inject X-Pomerium-Claim-* / JWT assertion into the upstream request. */
  passIdentityHeaders?: boolean;
}

export function buildRoute(spec: RouteSpec): Record<string, unknown> {
  const route: Record<string, unknown> = {
    from: `https://${spec.host}:8443`,
    to: spec.to,
  };

  const tls = spec.tls ?? {};
  if (tls.customCA !== undefined) route.tls_custom_ca = tls.customCA;
  if (tls.customCAFile !== undefined) route.tls_custom_ca_file = tls.customCAFile;
  if (tls.clientCert !== undefined) route.tls_client_cert = tls.clientCert;
  if (tls.clientKey !== undefined) route.tls_client_key = tls.clientKey;
  if (tls.clientCertFile !== undefined) route.tls_client_cert_file = tls.clientCertFile;
  if (tls.clientKeyFile !== undefined) route.tls_client_key_file = tls.clientKeyFile;
  if (tls.serverName !== undefined) route.tls_server_name = tls.serverName;
  if (tls.upstreamServerName !== undefined) route.tls_upstream_server_name = tls.upstreamServerName;
  if (tls.skipVerify !== undefined) route.tls_skip_verify = tls.skipVerify;
  if (tls.allowRenegotiation !== undefined) {
    route.tls_upstream_allow_renegotiation = tls.allowRenegotiation;
  }

  if (spec.passIdentityHeaders) route.pass_identity_headers = true;

  // Every route is authenticated: these are user-perspective e2e tests that log
  // in via the IdP and reach the protected upstream.
  route.policy = [{ allow: { or: [{ authenticated_user: true }] } }];
  return route;
}

/** Write a config with the given routes into .gen/ and return its host path. */
export function generateConfig(opts: {
  name: string;
  routes: RouteSpec[];
  extra?: Record<string, unknown>;
}): string {
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
    routes: opts.routes.map(buildRoute),
  };
  Object.assign(config, opts.extra);

  mkdirSync(GEN_DIR, { recursive: true });
  const file = path.join(GEN_DIR, `${opts.name}.yaml`);
  writeFileSync(file, JSON.stringify(config, null, 2));
  return file;
}

/**
 * The full route matrix shared by the behavior specs. Each route selects a
 * distinct upstream-TLS configuration; the specs assert per host.
 */
export function mainRoutes(): RouteSpec[] {
  const upstreamCA = upstreamCABase64();
  const wrongCA = wrongCABase64();
  const clientCertFile = CONTAINER_CERTS.clientCert;
  const clientKeyFile = CONTAINER_CERTS.clientKey;
  const tls = tlsUpstreamUrl;

  return [
    // --- Control + full-stack ------------------------------------------------
    { host: ROUTE_HOSTS.control, to: VERIFY_UPSTREAM_URL, passIdentityHeaders: true },
    {
      host: ROUTE_HOSTS.mtlsClaims,
      to: tls(MTLS_UPSTREAM_HOST),
      passIdentityHeaders: true,
      tls: { customCA: upstreamCA, clientCertFile, clientKeyFile },
    },

    // --- tls_custom_ca / tls_custom_ca_file ----------------------------------
    { host: ROUTE_HOSTS.customCa, to: tls(TLS_UPSTREAM_HOST), tls: { customCA: upstreamCA } },
    { host: ROUTE_HOSTS.customCaFile, to: tls(TLS_UPSTREAM_HOST), tls: { customCAFile: CONTAINER_CERTS.upstreamCA } },
    { host: ROUTE_HOSTS.customCaWrong, to: tls(TLS_UPSTREAM_HOST), tls: { customCA: wrongCA } },
    { host: ROUTE_HOSTS.customCaNone, to: tls(TLS_UPSTREAM_HOST) },

    // --- tls_client_cert[_file] (mTLS to upstream) ---------------------------
    {
      host: ROUTE_HOSTS.clientCert,
      to: tls(MTLS_UPSTREAM_HOST),
      tls: { customCA: upstreamCA, clientCert: clientCertBase64(), clientKey: clientKeyBase64() },
    },
    {
      host: ROUTE_HOSTS.clientCertFile,
      to: tls(MTLS_UPSTREAM_HOST),
      tls: { customCA: upstreamCA, clientCertFile, clientKeyFile },
    },
    { host: ROUTE_HOSTS.clientCertMissing, to: tls(MTLS_UPSTREAM_HOST), tls: { customCA: upstreamCA } },

    // --- tls_server_name / tls_upstream_server_name (SNI + verify name) ------
    { host: ROUTE_HOSTS.sniDefault, to: tls(SNI_UPSTREAM_HOST), tls: { customCA: upstreamCA } },
    { host: ROUTE_HOSTS.sniServerName, to: tls(SNI_UPSTREAM_HOST), tls: { customCA: upstreamCA, serverName: SNI_BACKEND_NAME } },
    { host: ROUTE_HOSTS.sniServerNameBogus, to: tls(SNI_UPSTREAM_HOST), tls: { customCA: upstreamCA, serverName: SNI_BOGUS_NAME } },
    { host: ROUTE_HOSTS.sniUpstreamName, to: tls(SNI_UPSTREAM_HOST), tls: { customCA: upstreamCA, upstreamServerName: SNI_BACKEND_NAME } },
    { host: ROUTE_HOSTS.sniUpstreamBogus, to: tls(SNI_UPSTREAM_HOST), tls: { customCA: upstreamCA, upstreamServerName: SNI_BOGUS_NAME } },
    // Precedence: server_name is WRONG (bogus), upstream_server_name is RIGHT.
    // A 200 proves upstream_server_name won for both SNI and verification.
    {
      host: ROUTE_HOSTS.sniPrecedence,
      to: tls(SNI_UPSTREAM_HOST),
      tls: { customCA: upstreamCA, serverName: SNI_BOGUS_NAME, upstreamServerName: SNI_BACKEND_NAME },
    },

    // --- tls_skip_verify (untrusted CA + name mismatch on the SNI upstream) --
    { host: ROUTE_HOSTS.skipVerifyOff, to: tls(SNI_UPSTREAM_HOST) },
    { host: ROUTE_HOSTS.skipVerifyOn, to: tls(SNI_UPSTREAM_HOST), tls: { skipVerify: true } },
    { host: ROUTE_HOSTS.skipVerifyWins, to: tls(SNI_UPSTREAM_HOST), tls: { skipVerify: true, customCA: wrongCA } },

    // --- tls_upstream_allow_renegotiation ------------------------------------
    { host: ROUTE_HOSTS.renegOff, to: tls(RENEG_UPSTREAM_HOST), tls: { customCA: upstreamCA } },
    { host: ROUTE_HOSTS.renegOn, to: tls(RENEG_UPSTREAM_HOST), tls: { customCA: upstreamCA, allowRenegotiation: true } },
  ];
}

let mainConfigCache: string | undefined;

/** The shared behavior-spec config (all routes). Cached per worker process. */
export function mainConfigFile(): string {
  mainConfigCache ??= generateConfig({ name: "main", routes: mainRoutes() });
  return mainConfigCache;
}
