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

/** True when the request died because nothing answered in time, not because it was refused. */
function isTimeout(err: unknown): boolean {
  const name = (err as { name?: string }).name;
  const causeName = (err as { cause?: { name?: string } }).cause?.name;
  return name === "TimeoutError" || name === "AbortError" || causeName === "TimeoutError";
}

/**
 * Assert nothing serves the metrics port. The port mapping always exists
 * (startPomerium publishes 9902 unconditionally), but with no metrics_address
 * there is no listener behind it.
 *
 * The proof is the SHAPE of the failure, not its error code: how Docker rejects
 * a mapped-but-unbacked port is platform-dependent. Some hosts refuse the
 * connection outright (ECONNREFUSED); on the Linux CI runners docker-proxy
 * accepts it and immediately closes, which undici reports as UND_ERR_SOCKET
 * ("other side closed"). Any such transport-level rejection means no HTTP
 * listener is there.
 *
 * A timeout is deliberately NOT accepted. "No answer at all" could be a hung
 * proxy rather than an absent listener, and treating it as proof would let this
 * case pass green against a wedged stack - which is the whole risk of asserting
 * an absence.
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
