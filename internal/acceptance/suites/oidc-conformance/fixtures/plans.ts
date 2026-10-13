// The conformance plans this suite runs, and which outcomes are acceptable.
//
// A module passes the e2e run when the driver saw no OP misbehavior and the
// suite reports:
//   - PASSED, or REVIEW (nothing failed; a screenshot awaits a human look,
//     and the driver has already checked what it shows), or
//   - WARNING, if every warning is one of ACCEPTED_WARNINGS.
// The modules in SKIPPED_MODULES must be SKIPPED instead (and only that, so
// the list stays current).

export interface PlanSpec {
  planName: string;
  variant?: Record<string, string>;
  /** Every module the plan contains, in plan order. */
  modules: string[];
}

export const PLANS: PlanSpec[] = [
  {
    planName: "oidcc-config-certification-test-plan",
    modules: ["oidcc-discovery-endpoint-verification"],
  },
  {
    planName: "oidcc-basic-certification-test-plan",
    variant: { server_metadata: "discovery", client_registration: "static_client" },
    modules: [
      "oidcc-server",
      "oidcc-response-type-missing",
      "oidcc-userinfo-get",
      "oidcc-userinfo-post-header",
      "oidcc-userinfo-post-body",
      "oidcc-ensure-request-without-nonce-succeeds-for-code-flow",
      "oidcc-scope-profile",
      "oidcc-scope-email",
      "oidcc-scope-address",
      "oidcc-scope-phone",
      "oidcc-scope-all",
      "oidcc-alternate-happy-flow",
      "oidcc-display-page",
      "oidcc-display-popup",
      "oidcc-prompt-login",
      "oidcc-prompt-none-not-logged-in",
      "oidcc-prompt-none-logged-in",
      "oidcc-max-age-1",
      "oidcc-max-age-10000",
      "oidcc-ensure-request-with-unknown-parameter-succeeds",
      "oidcc-id-token-hint",
      "oidcc-login-hint",
      "oidcc-ui-locales",
      "oidcc-claims-locales",
      "oidcc-ensure-request-with-acr-values-succeeds",
      "oidcc-codereuse",
      "oidcc-codereuse-30seconds",
      "oidcc-ensure-registered-redirect-uri",
      "oidcc-ensure-post-request-succeeds",
      "oidcc-server-client-secret-post",
      "oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported",
      "oidcc-claims-essential",
      "oidcc-ensure-request-object-with-redirect-uri",
      "oidcc-refresh-token",
      "oidcc-ensure-request-with-valid-pkce-succeeds",
    ],
  },
];

const SCOPES_BY_DESIGN =
  "The bridge advertises only the openid scope (scopes_supported), so the suite skips " +
  "scope-specific tests. It passes through whatever claims the identity provider released " +
  "for the Pomerium session; it does not filter claims by requested scope.";

/** Modules the suite skips, and why; keyed by module name. */
export const SKIPPED_MODULES: Record<string, string> = {
  "oidcc-scope-profile": SCOPES_BY_DESIGN,
  "oidcc-scope-email": SCOPES_BY_DESIGN,
  "oidcc-scope-address": SCOPES_BY_DESIGN,
  "oidcc-scope-phone": SCOPES_BY_DESIGN,
  "oidcc-scope-all": SCOPES_BY_DESIGN,
  "oidcc-alternate-happy-flow": SCOPES_BY_DESIGN,
  "oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported":
    "Request objects are not supported: the bridge rejects them with request_not_supported " +
    "and says so in discovery, which the suite treats as permitted and skips the rest.",
  "oidcc-refresh-token":
    "Refresh tokens are not issued (grant_types_supported is authorization_code only).",
};

/**
 * Warnings (by the suite's condition name) that are acceptable, with why. A
 * WARNING result is accepted only if all of its warnings are listed here.
 */
export const ACCEPTED_WARNINGS: Record<string, string> = {
  EnsureIdTokenDoesNotContainNonRequestedClaims:
    "By design the ID token carries the identity provider's claims about the user (email, " +
    "groups, ...) regardless of the requested scopes; see SCOPES_BY_DESIGN.",
  ValidateIdTokenACRClaimAgainstAcrValuesRequest:
    "acr_values is not supported (SHOULD-level); the bridge cannot vouch for an " +
    "authentication context class, and Keycloak sends no acr claim here.",
  EnsureUserInfoContainsName:
    "The claims parameter is not supported (claims_parameter_supported defaults to false), " +
    "and the Keycloak test realm does not release a name claim.",
};
