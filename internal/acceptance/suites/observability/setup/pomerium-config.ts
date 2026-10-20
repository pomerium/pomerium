// Per-test Pomerium configs, generated into .gen/ (gitignored) and bind-mounted
// by startPomerium. Written as JSON, which is valid YAML - no YAML dependency.
// The defaults are the QA plans' base config: one route from
// verify.localhost.pomerium.io to the pomerium/verify upstream.

import { mkdirSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import {
  AUTHENTICATE_URL,
  JAEGER_OTLP_HTTP_URL,
  KEYCLOAK_REALM_URL,
  SUITE_DIR,
  UPSTREAM_URL,
  VERIFY_URL,
} from "./constants.js";

const GEN_DIR = path.join(SUITE_DIR, ".gen");

/** In-container paths of the mounted certificate material (see certs.ts). */
const CONTAINER_CERT_FILE = "/certs/pomerium.crt";
const CONTAINER_KEY_FILE = "/certs/pomerium.key";

export interface ObservabilityConfigOptions {
  /** File name stem for the generated config (use the test case name). */
  name: string;
  /** allow_public_unauthenticated_access instead of allow_any_authenticated_user. */
  publicAccess?: boolean;
  /** access_log_fields. undefined = Pomerium's defaults; [] = log no fields. */
  accessLogFields?: string[];
  /** authorize_log_fields; same nil-vs-empty semantics as accessLogFields. */
  authorizeLogFields?: string[];
  /** metrics_address, e.g. ":9902". Omitted -> no metrics listener at all. */
  metricsAddress?: string;
  /** metrics_basic_auth (base64 of user:pass - or a malformed value under test). */
  metricsBasicAuth?: string;
  /** Any other top-level keys, spelled as in the config file. Merged LAST, so
   * these win over the typed options above - including replacing `routes`. */
  settings?: Record<string, unknown>;
}

/** Write a config variant into .gen/ and return its host path. */
export function generateConfig(opts: ObservabilityConfigOptions): string {
  const route: Record<string, unknown> = {
    from: VERIFY_URL,
    to: UPSTREAM_URL,
    pass_identity_headers: true,
  };
  if (opts.publicAccess) {
    route.allow_public_unauthenticated_access = true;
  } else {
    // Any signed-in user, so an unauthenticated request triggers the sign-in flow.
    route.allow_any_authenticated_user = true;
  }

  const config: Record<string, unknown> = {
    address: ":8443",
    authenticate_service_url: AUTHENTICATE_URL,
    idp_provider: "oidc",
    idp_provider_url: KEYCLOAK_REALM_URL,
    idp_client_id: "pomerium",
    idp_client_secret: "pomerium-e2e-secret",
    idp_scopes: ["openid", "profile", "email", "groups", "offline_access"],
    certificate_file: CONTAINER_CERT_FILE,
    certificate_key_file: CONTAINER_KEY_FILE,
    // Test-only secrets (reproducible tests) - NEVER use them in production.
    cookie_secret: "dj5y7E03ULP9YebCgHNIXmxWnWfYlVXCgwbm9IEdysI=",
    shared_secret: "0CdEkgO02jgxmgSC2AdkqIbFELAN4CGw0v0RY85xNr4=",
    // Access logs need info or below; debug also surfaces the config/tracing
    // diagnostics some specs assert on.
    log_level: "debug",
    jwt_claims_headers: { "X-Pomerium-Claim-Email": "email" },
    routes: [route],
  };

  if (opts.accessLogFields !== undefined) config.access_log_fields = opts.accessLogFields;
  if (opts.authorizeLogFields !== undefined) config.authorize_log_fields = opts.authorizeLogFields;
  if (opts.metricsAddress !== undefined) config.metrics_address = opts.metricsAddress;
  if (opts.metricsBasicAuth !== undefined) config.metrics_basic_auth = opts.metricsBasicAuth;
  Object.assign(config, opts.settings);

  mkdirSync(GEN_DIR, { recursive: true });
  const file = path.join(GEN_DIR, `${opts.name}.yaml`);
  writeFileSync(file, JSON.stringify(config, null, 2));
  return file;
}

/** otel_bsp_schedule_delay is an integer in MILLISECONDS, not a duration string. */
export const TRACING_TO_JAEGER: Record<string, unknown> = {
  otel_traces_exporter: "otlp",
  otel_exporter_otlp_endpoint: JAEGER_OTLP_HTTP_URL,
  otel_bsp_schedule_delay: 1000,
};

/**
 * A tracing-enabled config on the public route. `otel` overrides a baseline key,
 * or removes it by passing undefined - which is how the enablement matrix says
 * "the same thing but with X missing".
 */
export function tracingConfig(
  name: string,
  otel: Record<string, unknown> = {},
): string {
  const settings: Record<string, unknown> = {
    ...TRACING_TO_JAEGER,
    ...otel,
  };
  for (const [key, value] of Object.entries(settings)) {
    if (value === undefined) delete settings[key];
  }
  return generateConfig({ name, publicAccess: true, settings });
}
