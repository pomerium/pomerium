// Log-parsing and assertion helpers.
//
// Everything Pomerium emits (its own logs, Envoy access logs, authorize logs)
// is newline-delimited JSON on the container's stdout, captured line-by-line
// by startPomerium's log consumer. Two timing facts shape these helpers:
//   - Envoy flushes access logs on a ~1s interval, so a request's entry can
//     trail the response by over a second -> assertions must poll.
//   - Startup produces its own traffic-independent noise -> tests quiesce and
//     clear the buffer BEFORE generating the traffic under test, so the next
//     matching entry is unambiguously theirs.

import { expect } from "@playwright/test";
import { setTimeout as sleep } from "node:timers/promises";
import type { StartedPomerium } from "../setup/containers.js";

export type LogEntry = Record<string, unknown>;

export type LogKind = "access" | "authorize";

/**
 * Every configurable field name, mirroring pkg/logfields/access.go
 * AllAccessLogFields() and authorize.go AllAuthorizeLogFields(). Configuring a
 * subset must suppress all the others, so assertLogFields derives what has to
 * be ABSENT from these rather than each test naming the fields it expects not
 * to see.
 */
const FIELD_VOCABULARY: Record<LogKind, string[]> = {
  access: [
    "authority",
    "client-certificate",
    "cluster-stat-name",
    "duration",
    "forwarded-for",
    "ip",
    "method",
    "path",
    "query",
    "referer",
    "request-id",
    "response-code",
    "response-code-details",
    "size",
    "upstream-cluster",
    "user-agent",
  ],
  authorize: [
    "body",
    "check-request-id",
    "cluster-stat-name",
    "email",
    "envoy-route-checksum",
    "envoy-route-id",
    "headers",
    "host",
    "id-token",
    "id-token-claims",
    "impersonate-email",
    "impersonate-session-id",
    "impersonate-user-id",
    "ip",
    "mcp-method",
    "mcp-tool",
    "mcp-tool-parameters",
    "method",
    "path",
    "query",
    "removed-groups-count",
    "request-id",
    "route-checksum",
    "route-id",
    "service-account-id",
    "session-id",
    "user",
  ],
};

/**
 * Keys present on every entry regardless of the field configuration: zerolog's
 * own envelope, the service tag, and server-name - the services mode ("all"
 * here) that the control plane's context logger attaches to everything it
 * emits (internal/controlplane/server.go). TC-LOG-04 pins this list by
 * configuring zero fields, so a new context field fails there with a clear
 * message instead of breaking every field test.
 */
export const ENVELOPE_LOG_KEYS = ["level", "time", "service", "message", "server-name"];

/**
 * Keys present on an entry whatever the field configuration says.
 *
 * The authorize service always appends its decision, and names each reason
 * array after the outcome it explains (authorize/log.go): an allowed check
 * carries allow-why-true, a denied one allow-why-false. Both shapes occur in a
 * browser sign-in - the first request to a protected route is denied with
 * `user-unauthenticated` before the session exists - so the expectation is
 * derived from the entry's own decision rather than fixed.
 */
function alwaysOnKeys(entry: LogEntry, kind: LogKind): string[] {
  if (kind === "access") return ENVELOPE_LOG_KEYS;
  return [
    ...ENVELOPE_LOG_KEYS,
    "allow",
    entry.allow === true ? "allow-why-true" : "allow-why-false",
    "deny",
    entry.deny === true ? "deny-why-true" : "deny-why-false",
  ];
}

/** Parse captured stdout lines into JSON log entries, skipping non-JSON lines. */
function parseLogEntries(lines: string[]): LogEntry[] {
  const entries: LogEntry[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    try {
      entries.push(JSON.parse(trimmed) as LogEntry);
    } catch {
      // partial/interleaved line - not a log entry
    }
  }
  return entries;
}

/**
 * An Envoy access log entry for real traffic. /ping and /healthz are logged at
 * debug (internal/controlplane/grpc_accesslog.go), so the level check keeps the
 * readiness probes out even when no field distinguishes them.
 */
export const isAccessLog = (e: LogEntry): boolean =>
  e.message === "http-request" && e.level === "info";

/** Authorize service decision entry. */
export const isAuthorizeLog = (e: LogEntry): boolean => e.message === "authorize check";

/**
 * A line from the authenticate service. It tags itself in the message prefix
 * rather than in a `service` field, so that is what identifies it.
 */
export const isAuthenticateLog = (e: LogEntry): boolean =>
  typeof e.message === "string" && e.message.startsWith("authenticate: ");

/** Every captured entry matching the predicate (since the last clearLogs). */
export function entriesMatching(
  pomerium: StartedPomerium,
  predicate: (e: LogEntry) => boolean,
): LogEntry[] {
  return parseLogEntries(pomerium.logs()).filter(predicate);
}

/**
 * Poll the captured logs until an entry matches, tolerating Envoy's flush
 * delay. Throws with the tail of what WAS captured, for debuggability.
 */
export async function waitForEntry(
  pomerium: StartedPomerium,
  predicate: (e: LogEntry) => boolean,
  timeoutMs = 15_000,
): Promise<LogEntry> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const entry = parseLogEntries(pomerium.logs()).find(predicate);
    if (entry) return entry;
    if (Date.now() > deadline) {
      const tail = pomerium
        .logs()
        .slice(-15)
        .map((l) => l.trimEnd())
        .join("\n");
      throw new Error(
        `no log entry matched the predicate within ${timeoutMs}ms; last captured lines:\n${tail}`,
      );
    }
    await sleep(250);
  }
}

/**
 * Wait for the log stream to go quiet (no new lines for `quietMs`), then clear
 * the buffer. Run this after startup / sign-in and before generating the
 * traffic under test, so late-flushing entries from earlier requests cannot be
 * mistaken for the entry under assertion. On timeout it proceeds with whatever
 * has settled - the caller's own wait will fail with a better message.
 *
 * quietMs only has to exceed Envoy's ~1s access-log flush interval.
 */
export async function quiesceLogs(
  pomerium: StartedPomerium,
  quietMs = 1_500,
  timeoutMs = 15_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let count = pomerium.lineCount();
  let quietSince = Date.now();
  while (Date.now() - quietSince < quietMs && Date.now() < deadline) {
    await sleep(250);
    const next = pomerium.lineCount();
    if (next !== count) {
      count = next;
      quietSince = Date.now();
    }
  }
  pomerium.clearLogs();
}

/**
 * Assert an entry carries EXACTLY the configured fields: every expected field
 * present, every OTHER field of that log kind's vocabulary absent, and nothing
 * beyond the expected fields plus the always-on envelope.
 */
export function assertLogFields(entry: LogEntry, kind: LogKind, expected: string[]): void {
  const context = `log entry: ${JSON.stringify(entry)}`;
  const actual = Object.keys(entry);
  const alwaysOn = alwaysOnKeys(entry, kind);

  const missing = [...expected, ...alwaysOn].filter((k) => !(k in entry));
  expect(missing, `missing ${kind} log fields; ${context}`).toEqual([]);

  // A configurable field that was not asked for must not be logged.
  const leaked = FIELD_VOCABULARY[kind].filter((k) => !expected.includes(k) && k in entry);
  expect(leaked, `unconfigured ${kind} log fields were logged; ${context}`).toEqual([]);

  // Anything else is a new key from outside the field configuration entirely.
  const allowed = new Set([...expected, ...alwaysOn]);
  const unexpected = actual.filter((k) => !allowed.has(k));
  expect(unexpected, `unexpected keys outside the field configuration; ${context}`).toEqual([]);
}

/**
 * Apply assertLogFields to EVERY entry the window captured, not just one.
 *
 * Opening a route in a browser produces several entries - the sign-in
 * redirects, the route itself, whatever else the page fetches - and the field
 * configuration must hold for all of them. This is also the only way to make
 * the claim when no configured field identifies a particular request.
 */
export function assertAllLogFields(
  entries: LogEntry[],
  kind: LogKind,
  expected: string[],
): void {
  expect(entries.length, `expected at least one ${kind} log entry`).toBeGreaterThan(0);
  for (const entry of entries) {
    assertLogFields(entry, kind, expected);
  }
}
