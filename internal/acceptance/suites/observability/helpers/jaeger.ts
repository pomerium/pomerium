// Jaeger query-API client and span assertions.
//
// Pomerium exports OTLP to the Jaeger collector in-network; the tests read
// spans back through the classic query API on the fixed host port. Jaeger's
// store PERSISTS across the whole run (it boots once in global setup), so
// every assertion is scoped by a unique per-test marker path (helpers/traffic
// markerPath) - never by global trace counts.

import { setTimeout as sleep } from "node:timers/promises";
import { JAEGER_QUERY_URL } from "../setup/constants.js";

export interface JaegerKeyValue {
  key: string;
  value: unknown;
}

export interface JaegerSpan {
  traceID: string;
  spanID: string;
  operationName: string;
  processID: string;
  tags?: JaegerKeyValue[];
}

export interface JaegerProcess {
  serviceName: string;
  tags?: JaegerKeyValue[];
}

export interface JaegerTrace {
  traceID: string;
  spans: JaegerSpan[];
  processes: Record<string, JaegerProcess>;
}

/** service.name values Pomerium's own (non-Envoy) tracer providers register. */
const POMERIUM_SERVICES = [
  "Pomerium",
  "Control Plane",
  "Proxy",
  "Authenticate",
  "Authorize",
  "Data Broker",
];

export const ENVOY_SERVICE = "Envoy";

/** GET /api/services -> the service names Jaeger has seen so far. */
async function fetchServices(): Promise<string[]> {
  const res = await fetch(`${JAEGER_QUERY_URL}/api/services`, {
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) return [];
  const parsed = (await res.json()) as { data?: string[] | null };
  return parsed.data ?? [];
}

/**
 * GET /api/traces for one service. Unknown services (nothing exported yet)
 * are a normal outcome for the negative cases -> empty list, never an error.
 */
async function fetchTraces(service: string): Promise<JaegerTrace[]> {
  const params = new URLSearchParams({ service, lookback: "1h", limit: "200" });
  const res = await fetch(`${JAEGER_QUERY_URL}/api/traces?${params}`, {
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) return [];
  const parsed = (await res.json()) as { data?: JaegerTrace[] | null };
  return parsed.data ?? [];
}

function spanHasMarker(span: JaegerSpan, marker: string): boolean {
  if (span.operationName.includes(marker)) return true;
  return (span.tags ?? []).some((t) => typeof t.value === "string" && t.value.includes(marker));
}

/** Traces containing at least one span that references the marker path. */
function tracesWithMarker(traces: JaegerTrace[], markers: string[]): JaegerTrace[] {
  return traces.filter((trace) =>
    trace.spans.some((span) => markers.some((m) => spanHasMarker(span, m))),
  );
}

/** Distinct service names appearing in a trace (via its processes table). */
function serviceNamesOf(trace: JaegerTrace): Set<string> {
  return new Set(Object.values(trace.processes).map((p) => p.serviceName));
}

/** Spans of a trace that belong to the given service. */
function spansOfService(trace: JaegerTrace, service: string): JaegerSpan[] {
  return trace.spans.filter((span) => trace.processes[span.processID]?.serviceName === service);
}

/** Envoy's downstream-request spans for the marker path. */
export function ingressSpans(trace: JaegerTrace, marker: string): JaegerSpan[] {
  return spansOfService(trace, ENVOY_SERVICE).filter(
    (s) => s.operationName.startsWith("ingress:") && s.operationName.includes(marker),
  );
}

/** True when any of Pomerium's own services contributed a span to the trace. */
export function hasPomeriumSpans(trace: JaegerTrace): boolean {
  return [...serviceNamesOf(trace)].some((s) => POMERIUM_SERVICES.includes(s));
}

/** The Envoy process entry, which carries the pomerium.envoy resource attribute. */
export function envoyProcessOf(trace: JaegerTrace): JaegerProcess | undefined {
  return Object.values(trace.processes).find((p) => p.serviceName === ENVOY_SERVICE);
}

/**
 * Poll until an Envoy trace referencing the marker shows up AND satisfies
 * `until` (when given). The predicate matters because span families flush on
 * DIFFERENT schedules - Envoy's spans (batch delay from the config) can arrive
 * seconds before Pomerium's own SDK spans (default 5s batch delay) join the
 * same trace - so callers asserting on trace composition must keep polling
 * past the first partial snapshot.
 */
export async function waitForMarkerTrace(
  marker: string,
  opts: { timeoutMs?: number; until?: (trace: JaegerTrace) => boolean } = {},
): Promise<JaegerTrace> {
  const timeoutMs = opts.timeoutMs ?? 20_000;
  const until = opts.until ?? (() => true);
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const hits = tracesWithMarker(await fetchTraces(ENVOY_SERVICE), [marker]);
    const satisfied = hits.find(until);
    if (satisfied) return satisfied;
    if (Date.now() > deadline) {
      const detail = hits[0]
        ? `closest trace ${hits[0].traceID} had services ${JSON.stringify([
            ...serviceNamesOf(hits[0]),
          ])}`
        : `services known to Jaeger: ${JSON.stringify(await fetchServices())}`;
      throw new Error(
        `no Envoy trace referenced marker ${marker}${
          opts.until ? " and satisfied the predicate" : ""
        } within ${timeoutMs}ms (${detail})`,
      );
    }
    await sleep(500);
  }
}

/**
 * Assert that NO span referencing any of the markers reaches the collector.
 *
 * Jaeger keeps every span for the whole run and fetchTraces looks back an hour,
 * so a span exported at any point inside the window is still returned by a
 * query made after it: waiting out the window and then querying once is as
 * conclusive as polling throughout, for a seventh of the requests. The window
 * must exceed the batch-span-processor flush delay of the config under test.
 */
export async function expectNoMarkerSpans(
  marker: string | string[],
  opts: { services?: string[]; windowMs?: number } = {},
): Promise<void> {
  const markers = Array.isArray(marker) ? marker : [marker];
  const services = opts.services ?? [ENVOY_SERVICE, ...POMERIUM_SERVICES];
  await sleep(opts.windowMs ?? 6_000);

  const hits = await Promise.all(
    services.map(async (service) => ({
      service,
      traces: tracesWithMarker(await fetchTraces(service), markers),
    })),
  );
  const found = hits.filter((h) => h.traces.length > 0);
  if (found.length > 0) {
    throw new Error(
      `expected no spans for ${markers.join(", ")}, but found ` +
        found.map((h) => `${h.service}: trace ${h.traces[0].traceID}`).join("; "),
    );
  }
}
