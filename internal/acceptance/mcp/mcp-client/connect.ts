// Connect an MCP client to a Pomerium-fronted MCP server, performing the OAuth
// 2.1 browser sign-in with Playwright.
//
// Flow:
//   1. Attempt to connect. The server (Pomerium) returns 401, so the SDK runs
//      discovery + Dynamic Client Registration + PKCE and produces an authorize
//      URL via the OAuth provider, then throws UnauthorizedError.
//   2. Drive the browser through that URL: Pomerium redirects to Keycloak, we
//      submit credentials (reusing the acceptance suite's helpers), Pomerium
//      mints a session and issues an authorization code to our loopback server.
//   3. finishAuth(code) exchanges the code for tokens; reconnect with a fresh
//      transport that picks up the stored access token.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import type { Page } from "@playwright/test";

import { InMemoryOAuthProvider } from "./oauth-provider.js";
import { startCallbackServer } from "./callback-server.js";
import { submitLoginForm, waitForLoginPage } from "./keycloak-login.js";
import { CLIENT_NAME } from "./constants.js";
import type { TestUser } from "../../browser/fixtures/users.js";

export interface ConnectOptions {
  page: Page;
  serverUrl: string;
  user: TestUser;
  /** Max time to wait for the browser to deliver an authorization code. */
  authTimeoutMs?: number;
}

export interface ConnectedClient {
  client: Client;
  /** The connected transport (exposes the negotiated `protocolVersion`). */
  transport: StreamableHTTPClientTransport;
  close(): Promise<void>;
}

const CLIENT_INFO = { name: CLIENT_NAME, version: "1.0.0" };

export async function connectWithBrowserAuth(opts: ConnectOptions): Promise<ConnectedClient> {
  const { page, serverUrl, user, authTimeoutMs = 60_000 } = opts;
  const url = new URL(serverUrl);
  const callback = await startCallbackServer();

  try {
    const authProvider = new InMemoryOAuthProvider(callback.redirectUrl);

    // Step 1: probe — expected to throw UnauthorizedError after the SDK has
    // performed discovery/registration and produced an authorization URL.
    const probeTransport = new StreamableHTTPClientTransport(url, { authProvider });
    const probeClient = new Client(CLIENT_INFO);
    try {
      await probeClient.connect(probeTransport);
      // Unexpected for our protected route, but handle it: already authorized.
      return { client: probeClient, transport: probeTransport, close: () => probeClient.close() };
    } catch (err) {
      if (!(err instanceof UnauthorizedError)) throw err;
    }

    // From here the probe is only kept alive to complete the token exchange, so
    // make sure it's torn down whether finishAuth succeeds or throws.
    try {
      const authorizationUrl = authProvider.authorizationUrl;
      if (!authorizationUrl) {
        throw new Error("MCP SDK did not produce an authorization URL after the 401 challenge");
      }

      // Step 2: browser sign-in.
      await page.goto(authorizationUrl.toString());
      await waitForLoginPage(page);
      await submitLoginForm(page, user);
      const code = await callback.waitForCode(authTimeoutMs);

      // Step 3: exchange the code, then reconnect with the stored token.
      await probeTransport.finishAuth(code);
    } finally {
      // Closing the client also closes its underlying transport.
      await probeClient.close();
    }

    const transport = new StreamableHTTPClientTransport(url, { authProvider });
    const client = new Client(CLIENT_INFO);
    await client.connect(transport);
    return { client, transport, close: () => client.close() };
  } finally {
    callback.close();
  }
}
