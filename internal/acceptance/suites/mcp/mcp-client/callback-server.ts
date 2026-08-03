// A tiny loopback HTTP server that captures the OAuth authorization code from
// the final redirect. The MCP client registers http://127.0.0.1:<port>/callback
// as its redirect_uri (via DCR); after the browser completes sign-in, Pomerium
// redirects there with ?code=..., which we capture and hand back to the SDK.

import http from "node:http";
import type { AddressInfo } from "node:net";

export interface CallbackServer {
  /** Loopback redirect URI registered with the authorization server. */
  redirectUrl: string;
  /** Resolves with the authorization code, or rejects on error/timeout. */
  waitForCode(timeoutMs?: number): Promise<string>;
  close(): void;
}

export async function startCallbackServer(): Promise<CallbackServer> {
  let resolveCode!: (code: string) => void;
  let rejectCode!: (err: Error) => void;
  const codePromise = new Promise<string>((resolve, reject) => {
    resolveCode = resolve;
    rejectCode = reject;
  });

  const server = http.createServer((req, res) => {
    const requestUrl = new URL(req.url ?? "/", "http://127.0.0.1");
    if (requestUrl.pathname !== "/callback") {
      res.writeHead(404);
      res.end();
      return;
    }
    const code = requestUrl.searchParams.get("code");
    const error = requestUrl.searchParams.get("error");
    res.writeHead(200, { "content-type": "text/html" });
    res.end(
      "<!doctype html><html><body>Authorization complete. You may close this window.</body></html>",
    );
    if (code) {
      resolveCode(code);
    } else {
      rejectCode(
        new Error(`OAuth callback did not include a code (error=${error ?? "none"})`),
      );
    }
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  return {
    redirectUrl: `http://127.0.0.1:${port}/callback`,
    waitForCode(timeoutMs = 60_000): Promise<string> {
      let timer: ReturnType<typeof setTimeout>;
      const timeout = new Promise<string>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("timed out waiting for the OAuth authorization code")),
          timeoutMs,
        );
      });
      // Clear the timer once the code arrives so a pending timeout does not keep
      // the worker's event loop alive after the test completes.
      return Promise.race([codePromise, timeout]).finally(() => clearTimeout(timer));
    },
    close(): void {
      server.close();
    },
  };
}
