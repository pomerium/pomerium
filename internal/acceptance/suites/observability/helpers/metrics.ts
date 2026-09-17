// Prometheus metrics-endpoint helpers. On the fixed host port 9902:
//   /metrics        -> Pomerium's aggregated handler (pomerium_* + scraped
//                      envoy_*; the only path metrics_basic_auth covers)
//   /metrics/envoy  -> Envoy admin /stats/prometheus (raw envoy_*)

import { METRICS_URL } from "../setup/constants.js";

export interface ScrapeResult {
  status: number;
  body: string;
  headers: Headers;
}

export function basicAuth64(user: string, pass: string): string {
  return Buffer.from(`${user}:${pass}`).toString("base64");
}

/** Fetch a metrics path, optionally with basic-auth credentials. */
export async function scrapeMetrics(
  metricsPath: "/metrics" | "/metrics/envoy" = "/metrics",
  opts: { auth?: { user: string; pass: string } } = {},
): Promise<ScrapeResult> {
  const headers: Record<string, string> = {};
  if (opts.auth) {
    headers.Authorization = `Basic ${basicAuth64(opts.auth.user, opts.auth.pass)}`;
  }
  const res = await fetch(`${METRICS_URL}${metricsPath}`, {
    headers,
    signal: AbortSignal.timeout(10_000),
  });
  return { status: res.status, body: await res.text(), headers: res.headers };
}

/** The metric family a Prometheus sample line belongs to ("" for non-samples). */
function sampleName(line: string): string {
  if (!line || line.startsWith("#")) return "";
  return line.split(/[{ ]/, 1)[0];
}

/** Metric (family) names present in a Prometheus text-format body. */
export function metricNames(body: string): Set<string> {
  const names = new Set(body.split("\n").map(sampleName));
  names.delete("");
  return names;
}

/** Sum a metric's values across all its label sets; 0 when absent. */
export function metricValue(body: string, name: string): number {
  let sum = 0;
  for (const line of body.split("\n")) {
    if (sampleName(line) !== name) continue;
    const value = Number.parseFloat(line.slice(line.lastIndexOf(" ") + 1));
    if (Number.isFinite(value)) sum += value;
  }
  return sum;
}

/** True when the request died because nothing answered in time, not because it was refused. */
function isTimeout(err: unknown): boolean {
  const name = (err as { name?: string }).name;
  const causeName = (err as { cause?: { name?: string } }).cause?.name;
  return name === "TimeoutError" || name === "AbortError" || causeName === "TimeoutError";
}

/**
 * Assert nothing serves the metrics port. The mapping always exists, so the proof
 * is the SHAPE of the failure, not its code: hosts either refuse outright
 * (ECONNREFUSED) or, on the Linux CI runners, accept and immediately close
 * (UND_ERR_SOCKET). Any transport-level rejection means no listener.
 *
 * A timeout is deliberately NOT accepted: no answer at all could be a hung proxy,
 * and treating that as proof would pass green against a wedged stack.
 */
export async function expectMetricsPortClosed(): Promise<void> {
  let res: Response;
  try {
    res = await fetch(`${METRICS_URL}/metrics`, { signal: AbortSignal.timeout(5_000) });
  } catch (err) {
    if (isTimeout(err)) {
      throw new Error(
        `the metrics port neither answered nor refused within 5s - the stack may be ` +
          `wedged, which is not evidence that the listener is absent: ${err}`,
        { cause: err },
      );
    }
    return; // refused / reset / closed - the expected outcome
  }
  throw new Error(
    `expected the metrics port to be closed, but got HTTP ${res.status}: ${
      (await res.text()).slice(0, 200)
    }`,
  );
}
