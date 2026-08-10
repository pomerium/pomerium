// Prometheus metrics-endpoint helpers.
//
// The metrics listener (metrics_address) is an Envoy-fronted listener on the
// fixed host port 9902 (published unconditionally by startPomerium):
//   /metrics        -> Pomerium's aggregated handler (pomerium_* + scraped
//                      envoy_* merged; the only path metrics_basic_auth covers)
//   /metrics/envoy  -> rewritten to Envoy admin /stats/prometheus (raw envoy_*)

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

/** Socket-level errors that mean "nothing is listening behind the mapping". */
const CLOSED_PORT_CODES = ["ECONNREFUSED", "ECONNRESET", "EPIPE", "ECONNABORTED"];

/**
 * Assert nothing serves the metrics port. The port mapping always exists
 * (startPomerium publishes 9902 unconditionally), but with no metrics_address
 * there is no listener behind it: depending on platform the connection is
 * refused outright or accepted by the docker proxy and immediately dropped.
 *
 * Only those connection-level failures count as proof. A timeout or a DNS/TLS
 * error is NOT evidence of a closed port - treating them as such would let this
 * pass green against a wedged stack - so anything else is re-thrown.
 */
export async function expectMetricsPortClosed(): Promise<void> {
  let res: Response;
  try {
    res = await fetch(`${METRICS_URL}/metrics`, { signal: AbortSignal.timeout(5_000) });
  } catch (err) {
    const code = (err as { cause?: { code?: string }; code?: string }).cause?.code
      ?? (err as { code?: string }).code;
    if (code && CLOSED_PORT_CODES.includes(code)) return; // the expected outcome
    throw new Error(
      `expected a closed metrics port, but the request failed for another reason ` +
        `(code=${code ?? "none"}): ${err}`,
      { cause: err },
    );
  }
  throw new Error(
    `expected the metrics port to be closed, but got HTTP ${res.status}: ${
      (await res.text()).slice(0, 200)
    }`,
  );
}
