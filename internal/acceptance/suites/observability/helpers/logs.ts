// Log-parsing and assertion helpers.
//
// Everything Pomerium emits is newline-delimited JSON on stdout, captured by
// startPomerium's log consumer. Two timing facts shape these helpers: Envoy
// flushes access logs on a ~1s interval, so assertions must poll; and startup
// produces its own noise, so tests quiesce and clear the buffer BEFORE the
// traffic under test.

import { expect } from "@playwright/test";
import { setTimeout as sleep } from "node:timers/promises";
import type { StartedPomerium } from "../setup/containers.js";

export type LogEntry = Record<string, unknown>;

export type LogKind = "access" | "authorize";

/**
 * Present on every entry whatever the field configuration says: zerolog's
 * envelope plus the context fields the control plane attaches. TC-LOG-04 pins
 * this list by configuring zero fields, so a new context field fails there
 * rather than in every field test.
 */
export const ENVELOPE_LOG_KEYS = ["level", "time", "service", "message", "server-name"];

/**
 * Authorize always appends its decision, naming each reason array after the
 * outcome it explains: an allowed check carries allow-why-true, a denied one
 * allow-why-false. A browser sign-in produces both, so the expectation is
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
 * debug, so the level check excludes readiness probes - no field distinguishes them.
 */
export const isAccessLog = (e: LogEntry): boolean =>
  e.message === "http-request" && e.level === "info";

/** Authorize service decision entry. */
export const isAuthorizeLog = (e: LogEntry): boolean => e.message === "authorize check";

/** The authenticate service tags itself in the message prefix, not in `service`. */
export const isAuthenticateLog = (e: LogEntry): boolean =>
  typeof e.message === "string" && e.message.startsWith("authenticate: ");

/** Every captured entry matching the predicate (since the last clearLogs). */
export function entriesMatching(
  pomerium: StartedPomerium,
  predicate: (e: LogEntry) => boolean,
): LogEntry[] {
  return parseLogEntries(pomerium.logs()).filter(predicate);
}

/** Poll until an entry matches, tolerating Envoy's flush delay. Throws with the tail. */
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
 * Wait for the stream to go quiet, then clear the buffer. Run it before the
 * traffic under test so a late-flushing earlier entry cannot be mistaken for
 * the one under assertion. quietMs only has to exceed Envoy's ~1s flush.
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
 * present, and no key at all beyond those plus the always-on envelope.
 */
export function assertLogFields(entry: LogEntry, kind: LogKind, expected: string[]): void {
  const context = `log entry: ${JSON.stringify(entry)}`;
  const actual = Object.keys(entry);
  const alwaysOn = alwaysOnKeys(entry, kind);

  const missing = [...expected, ...alwaysOn].filter((k) => !(k in entry));
  expect(missing, `missing ${kind} log fields; ${context}`).toEqual([]);

  // Anything not asked for must be absent. Checking the complement of the
  // allowed set covers both unconfigured fields and entirely new keys, and
  // cannot drift against pkg/logfields the way a mirrored list would.
  const allowed = new Set([...expected, ...alwaysOn]);
  const unexpected = actual.filter((k) => !allowed.has(k));
  expect(unexpected, `${kind} log fields that were not configured; ${context}`).toEqual([]);
}

/**
 * assertLogFields over EVERY captured entry. A browser navigation produces
 * several, and the field configuration must hold for all of them - which is
 * also the only way to make the claim when no configured field identifies a
 * single request.
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
