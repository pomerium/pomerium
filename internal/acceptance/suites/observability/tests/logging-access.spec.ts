// Access-log field configuration (QA plan: Core.Logging / access_log_fields).
//
// Access logs are Envoy's per-request entries, shipped to the control plane
// and emitted as JSON on stdout with message "http-request" and service
// "envoy". The configured fields - and ONLY those - appear as top-level keys
// next to the always-on envelope, so these tests assert exact key sets:
// assertLogFields derives the must-be-absent set from the full field
// vocabulary in helpers/logs.ts (mirroring pkg/logfields/access.go), so each
// test only names what it configured.
//
// The route is `allow_any_authenticated_user: true` and is opened in a real
// browser after a real Keycloak sign-in, so the field configuration is asserted
// against the traffic a user actually produces - the sign-in redirects through
// the authenticate host included, not just one synthetic request.

import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import {
  assertAllLogFields,
  assertLogFields,
  ENVELOPE_LOG_KEYS,
  entriesMatching,
  isAccessLog,
  quiesceLogs,
  waitForEntry,
} from "../helpers/logs.js";
import { openMarker, signIn } from "../helpers/traffic.js";
import { withPomerium } from "../setup/containers.js";
import { VERIFY_URL } from "../setup/constants.js";
import { generateConfig } from "../setup/pomerium-config.js";

// pkg/logfields/access.go defaultAccessLogFields, verbatim.
const DEFAULT_ACCESS_FIELDS = [
  "upstream-cluster",
  "method",
  "authority",
  "path",
  "user-agent",
  "referer",
  "forwarded-for",
  "request-id",
  "duration",
  "size",
  "response-code",
  "response-code-details",
];

test.describe("Access log fields", () => {
  test("TC-LOG-01: defaults - exactly the 12 default fields are logged", async ({ page }) => {
    const configFile = generateConfig({
      name: "log-access-defaults",
      // no accessLogFields -> Pomerium falls back to its built-in defaults
    });
    await withPomerium({ configFile }, async (pomerium) => {
      // Sign in first, then drop the sign-in traffic: what follows is the
      // request under assertion.
      await signIn(page, VERIFY_URL);
      await quiesceLogs(pomerium);

      const marker = await openMarker(page, "log01");

      const entry = await waitForEntry(pomerium, (e) => isAccessLog(e) && e.path === marker);
      // Exactness also proves the non-default fields (ip, query,
      // client-certificate, cluster-stat-name) stay out.
      assertLogFields(entry, "access", DEFAULT_ACCESS_FIELDS);

      expect(entry.service).toBe("envoy");
      expect(entry.method).toBe("GET");
      expect(entry["response-code"]).toBe(200);
      expect(String(entry["upstream-cluster"])).toMatch(/^route-/);
      // A browser navigation, unlike a request context, carries a real UA.
      expect(String(entry["user-agent"])).toContain("Mozilla/5.0");
      // The logged authority is captured AFTER Pomerium's default upstream
      // host rewrite, so it is the upstream's ("upstream:8000"), not the
      // route's public hostname.
      expect(String(entry.authority)).not.toBe("");

      // The same field set must hold for every request the browser made.
      assertAllLogFields(entriesMatching(pomerium, isAccessLog), "access", DEFAULT_ACCESS_FIELDS);
    });
  });

  test("TC-LOG-02: a single configured field suppresses all others", async ({ page }) => {
    const configFile = generateConfig({
      name: "log-access-single",
      accessLogFields: ["method"],
    });
    await withPomerium({ configFile }, async (pomerium) => {
      await signIn(page, VERIFY_URL);
      await quiesceLogs(pomerium);

      await openMarker(page, "log02");

      // With only `method` configured nothing identifies an individual
      // request, so the claim is made across every entry instead: not one of
      // them may carry path, authority, request-id or anything else.
      await waitForEntry(pomerium, isAccessLog);
      const entries = entriesMatching(pomerium, isAccessLog);
      assertAllLogFields(entries, "access", ["method"]);
      expect(entries.every((e) => e.method === "GET")).toBe(true);
    });
  });

  test("TC-LOG-03: headers.<Name> logs a nested headers object with only that header", async ({
    page,
  }) => {
    const configFile = generateConfig({
      name: "log-access-header",
      accessLogFields: ["path", "headers.X-Marker"],
    });
    await withPomerium({ configFile }, async (pomerium) => {
      await signIn(page, VERIFY_URL);
      await quiesceLogs(pomerium);

      const headerValue = randomUUID();
      const marker = await openMarker(page, "log03", {
        headers: { "X-Marker": headerValue, "X-Other": "must-not-be-logged" },
      });

      const entry = await waitForEntry(pomerium, (e) => isAccessLog(e) && e.path === marker);
      assertLogFields(entry, "access", ["path", "headers"]);

      // The header key may surface canonicalized (X-Marker) or lowercased
      // depending on the HTTP/2 header pipeline - accept either, but the
      // value must match and no OTHER header may be present.
      const headers = entry.headers as Record<string, unknown>;
      expect(headers).toBeInstanceOf(Object);
      const keys = Object.keys(headers);
      expect(keys.map((k) => k.toLowerCase())).toEqual(["x-marker"]);
      expect(headers[keys[0]]).toBe(headerValue);
    });
  });

  test("TC-LOG-04: an empty field list logs the envelope only", async ({ page }) => {
    const configFile = generateConfig({
      name: "log-access-empty",
      // An explicit empty list is honored as "log no fields" (a nil list would
      // mean defaults), which makes the entry's key set exactly the envelope -
      // pinning ENVELOPE_LOG_KEYS for every other assertion in the suite.
      accessLogFields: [],
    });
    await withPomerium({ configFile }, async (pomerium) => {
      await signIn(page, VERIFY_URL);
      await quiesceLogs(pomerium);

      await openMarker(page, "log04");

      await waitForEntry(pomerium, isAccessLog);
      const entries = entriesMatching(pomerium, isAccessLog);
      expect(entries.length).toBeGreaterThan(0);
      for (const entry of entries) {
        expect(Object.keys(entry).sort()).toEqual([...ENVELOPE_LOG_KEYS].sort());
        expect(entry.service).toBe("envoy");
      }
    });
  });
});
