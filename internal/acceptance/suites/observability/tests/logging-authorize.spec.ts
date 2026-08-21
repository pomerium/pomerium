// Authorize-log field configuration and the sign-in decision trail
// (QA plan: Core.Logging / authorize_log_fields).
//
// Authorize logs are the authorize service's per-check entries, message
// "authorize check". On top of the configured fields the DECISION is always
// appended - `allow`, `deny`, and a reason array named after each outcome.
//
// Every case drives a real browser, so the checks asserted are the ones a user
// causes: a denial before the session exists, the authenticate service's own
// routes, then the allowed request.
//
// pkg/logfields/authorize.go configures 18 defaults, but several only
// materialize in specific situations (impersonate-* when impersonating,
// service-account-id for service accounts, removed-groups-count when group
// filtering removed groups). A plain logged-in request materializes the 13
// asserted below.

import { expect, test } from "@playwright/test";
import {
  assertAllLogFields,
  assertLogFields,
  entriesMatching,
  isAuthenticateLog,
  isAuthorizeLog,
  quiesceLogs,
  waitForEntry,
  type LogEntry,
} from "../helpers/logs.js";
import { openMarker, signIn } from "../helpers/traffic.js";
import { withPomerium } from "../setup/containers.js";
import { AUTHENTICATE_HOSTNAME, TEST_USER, VERIFY_HOSTNAME, VERIFY_URL } from "../setup/constants.js";
import { generateConfig } from "../setup/pomerium-config.js";

// The defaults that materialize for a plain logged-in user request.
const MATERIALIZED_DEFAULT_AUTHORIZE_FIELDS = [
  "request-id",
  "check-request-id",
  "method",
  "path",
  "host",
  "ip",
  "session-id",
  "user",
  "email",
  "envoy-route-checksum",
  "envoy-route-id",
  "route-checksum",
  "route-id",
];

const onHost = (host: string) => (e: LogEntry) =>
  isAuthorizeLog(e) && String(e.host).startsWith(host);

test.describe("Authorize log fields", () => {
  test("TC-LOG-10: defaults - the default field set for a signed-in request", async ({ page }) => {
    const configFile = generateConfig({
      name: "log-authz-defaults",
      // no authorizeLogFields -> Pomerium falls back to its built-in defaults
    });
    await withPomerium({ configFile }, async (pomerium) => {
      await signIn(page, VERIFY_URL);
      await quiesceLogs(pomerium);

      const marker = await openMarker(page, "log10");

      const entry = await waitForEntry(pomerium, (e) => isAuthorizeLog(e) && e.path === marker);
      assertLogFields(entry, "authorize", MATERIALIZED_DEFAULT_AUTHORIZE_FIELDS);

      expect(entry.service).toBe("authorize");
      expect(entry.email).toBe(TEST_USER.email);
      expect(typeof entry.user).toBe("string");
      expect(String(entry.host)).toContain(VERIFY_HOSTNAME);
      expect(entry.allow).toBe(true);
      expect(Array.isArray(entry["allow-why-true"])).toBe(true);
      expect(entry.deny).toBe(false);
    });
  });

  test("TC-LOG-11: headers.Cookie logs only that header; decision fields survive", async ({
    page,
  }) => {
    const configFile = generateConfig({
      name: "log-authz-cookie",
      authorizeLogFields: ["headers.Cookie"],
    });
    await withPomerium({ configFile }, async (pomerium) => {
      await signIn(page, VERIFY_URL);
      await quiesceLogs(pomerium);

      await openMarker(page, "log11");

      // No configured field identifies a request, so the claim is made across
      // every check: none may carry email, user, session-id, path or host.
      await waitForEntry(pomerium, isAuthorizeLog);
      const entries = entriesMatching(pomerium, isAuthorizeLog);
      assertAllLogFields(entries, "authorize", ["headers"]);

      const withCookie = entries.filter((e) => {
        const headers = (e.headers ?? {}) as Record<string, unknown>;
        const key = Object.keys(headers).find((k) => k.toLowerCase() === "cookie");
        return key !== undefined && String(headers[key]).includes("_pomerium");
      });
      expect(
        withCookie.length,
        `expected a check carrying the session cookie; got ${JSON.stringify(entries)}`,
      ).toBeGreaterThan(0);
    });
  });

  test("TC-LOG-12: a single configured field suppresses the other defaults", async ({ page }) => {
    const configFile = generateConfig({
      name: "log-authz-single",
      authorizeLogFields: ["email"],
    });
    await withPomerium({ configFile }, async (pomerium) => {
      await signIn(page, VERIFY_URL);
      await quiesceLogs(pomerium);

      await openMarker(page, "log12");

      await waitForEntry(pomerium, isAuthorizeLog);
      const entries = entriesMatching(pomerium, isAuthorizeLog);
      assertAllLogFields(entries, "authorize", ["email"]);
      expect(entries.some((e) => e.email === TEST_USER.email)).toBe(true);
    });
  });
});

test.describe("Sign-in decision trail", () => {
  test("TC-LOG-13: opening the route in a browser logs the authenticate and authorize path", async ({
    page,
  }) => {
    const configFile = generateConfig({ name: "log-authz-signin" });
    await withPomerium({ configFile }, async (pomerium) => {
      // Quiesce BEFORE signing in: here the sign-in traffic IS the subject.
      await quiesceLogs(pomerium);
      await signIn(page, VERIFY_URL);

      // The identified check on the route is the last thing the flow produces,
      // so waiting for it means the whole trail has been logged.
      const allowed = await waitForEntry(
        pomerium,
        (e) => onHost(VERIFY_HOSTNAME)(e) && e.allow === true && e.email === TEST_USER.email,
      );
      // `user-ok` is the reason allow_any_authenticated_user produces - the
      // policy under test, distinct from the `pomerium-route` reason the
      // internal endpoints get.
      expect(allowed["allow-why-true"]).toContain("user-ok");
      expect(String(allowed["session-id"]), "the allowed check carries a session").not.toBe("");

      const trail = entriesMatching(pomerium, isAuthorizeLog);

      // 1. The first request arrives without a session and is refused, which is
      //    what starts the sign-in. Note the reason array is named after the
      //    outcome: a denial carries allow-why-false, never allow-why-true.
      const deniedAt = trail.findIndex((e) => onHost(VERIFY_HOSTNAME)(e) && e.allow === false);
      expect(deniedAt, "expected an unauthenticated check on the route").toBeGreaterThanOrEqual(0);
      const denied = trail[deniedAt];
      expect(denied["allow-why-false"]).toContain("user-unauthenticated");
      expect(denied).not.toHaveProperty("allow-why-true");
      expect(denied.email).toBe("");

      // ...and it precedes the identified one: the denial is the trigger, not a
      // stray failure after the fact.
      const allowedAt = trail.findIndex(
        (e) => onHost(VERIFY_HOSTNAME)(e) && e.email === TEST_USER.email,
      );
      expect(allowedAt).toBeGreaterThan(deniedAt);

      // 2. Pomerium's own endpoints are authorized as internal routes rather
      //    than by the route policy - on the authenticate host during the OIDC
      //    round trip, and once on the route's own host where the session is
      //    planted before the retried request.
      const authenticateChecks = trail.filter(onHost(AUTHENTICATE_HOSTNAME));
      expect(
        authenticateChecks.length,
        "expected authorize checks on the authenticate host",
      ).toBeGreaterThan(0);
      expect(authenticateChecks.some((e) => String(e.path).startsWith("/.pomerium/"))).toBe(true);
      expect(authenticateChecks.every((e) => e.allow === true)).toBe(true);
      expect(authenticateChecks[0]["allow-why-true"]).toContain("pomerium-route");

      const internalOnRoute = trail
        .slice(deniedAt, allowedAt)
        .filter((e) => onHost(VERIFY_HOSTNAME)(e) && e.allow === true);
      expect(
        internalOnRoute.every((e) => (e["allow-why-true"] as string[]).includes("pomerium-route")),
        "pre-session checks on the route host are internal routes, not policy hits",
      ).toBe(true);

      // 3. The authenticate service logs the session handling itself. It tags
      //    itself in the message prefix, not in a `service` field.
      const authenticateLogs = entriesMatching(pomerium, isAuthenticateLog);
      expect(
        authenticateLogs.map((e) => e.message),
        "expected the authenticate service to log the sign-in",
      ).not.toEqual([]);
    });
  });
});
