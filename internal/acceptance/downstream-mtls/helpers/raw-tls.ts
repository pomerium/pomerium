// Raw TLS probing, for cases where there is no HTTP response to inspect.
//
// Under `enforcement: reject_connection` Pomerium requires a trusted client
// certificate during the TLS handshake itself. With TLS 1.3 the client sees
// the server's rejection only on the first read/write after the handshake, so
// the probe always attempts a minimal HTTP exchange and classifies the result.

import * as fs from "node:fs";
import * as tls from "node:tls";

export interface RawTLSOptions {
  host?: string; // dial target (default 127.0.0.1 - *.localhost.pomerium.io)
  servername: string; // SNI / Host header
  port?: number;
  certPath?: string;
  keyPath?: string;
  timeoutMs?: number;
}

export interface RawTLSResult {
  /** True when the TLS handshake AND a minimal HTTP exchange succeeded. */
  ok: boolean;
  /** First line of the HTTP response, when one was received. */
  statusLine?: string;
  /** Error message when the connection was rejected. */
  error?: string;
}

/**
 * Perform a TLS handshake (optionally presenting a client certificate) and a
 * minimal HTTP/1.1 request. Server certificate verification is disabled - the
 * stack uses a per-run test CA.
 */
export function rawTLSProbe(opts: RawTLSOptions): Promise<RawTLSResult> {
  const {
    host = "127.0.0.1",
    servername,
    port = 8443,
    certPath,
    keyPath,
    timeoutMs = 10_000,
  } = opts;

  return new Promise((resolve) => {
    let settled = false;
    const done = (result: RawTLSResult) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    const socket = tls.connect({
      host,
      port,
      servername,
      rejectUnauthorized: false,
      cert: certPath ? fs.readFileSync(certPath) : undefined,
      key: keyPath ? fs.readFileSync(keyPath) : undefined,
    });

    socket.setTimeout(timeoutMs, () => done({ ok: false, error: "timeout" }));
    socket.on("error", (err) => done({ ok: false, error: String(err) }));
    socket.on("secureConnect", () => {
      // TLS 1.3: the server's certificate_required alert may only surface on
      // the first read/write, so always follow up with a real request.
      socket.write(`GET /healthz HTTP/1.1\r\nHost: ${servername}\r\nConnection: close\r\n\r\n`);
    });
    socket.on("data", (data) => {
      done({ ok: true, statusLine: data.toString().split("\r\n")[0] });
    });
    socket.on("close", () => done({ ok: false, error: "connection closed before any HTTP response" }));
  });
}

/** Poll until a raw TLS probe succeeds (used as a readiness gate). */
export async function waitForTLS(opts: RawTLSOptions, deadlineMs = 60_000): Promise<void> {
  const start = Date.now();
  let last: RawTLSResult = { ok: false, error: "not attempted" };
  while (Date.now() - start < deadlineMs) {
    last = await rawTLSProbe({ ...opts, timeoutMs: 3_000 });
    if (last.ok) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`TLS endpoint not ready after ${deadlineMs}ms: ${last.error}`);
}
