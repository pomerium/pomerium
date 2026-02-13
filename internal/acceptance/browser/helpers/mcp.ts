/**
 * MCP test helpers for E2E acceptance tests.
 *
 * Implements the full MCP OAuth 2.1 flow:
 *   1. Dynamic client registration (RFC 7591)
 *   2. Authorization with PKCE (RFC 7636)
 *   3. Token exchange
 *   4. Bearer-authenticated MCP requests
 */

import { Page } from "@playwright/test";
import { createHash, randomBytes } from "crypto";
import { mcpUrls, mcpPaths, buildUrl, timeouts } from "../fixtures/test-data.js";
import { TestUser, getKeycloakUsername } from "../fixtures/users.js";

// ---------------------------------------------------------------------------
// PKCE helpers
// ---------------------------------------------------------------------------

/** Generate a random code_verifier (43–128 chars, URL-safe). */
export function generateCodeVerifier(): string {
  return randomBytes(32).toString("base64url");
}

/** Compute S256 code_challenge from a code_verifier. */
export function generateCodeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

// ---------------------------------------------------------------------------
// OAuth client registration
// ---------------------------------------------------------------------------

export interface ClientRegistration {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: string;
}

// Use a path on the MCP domain so the browser can reach it (TLS handshake
// succeeds with ignoreHTTPSErrors).  page.route() intercepts before Pomerium
// processes the request, so it never reaches the proxy.
const CALLBACK_URL =
  (process.env.MCP_URL || "https://mcp.localhost.pomerium.io:8443") +
  "/oauth-test-callback";

/**
 * Register a dynamic OAuth client with Pomerium's MCP endpoint.
 * Uses page.request so the call goes from the Node process (not the browser).
 */
export async function registerMcpClient(
  page: Page
): Promise<ClientRegistration> {
  const registerUrl = buildUrl(mcpUrls.server, mcpPaths.register);
  const response = await page.request.post(registerUrl, {
    data: {
      redirect_uris: [CALLBACK_URL],
      client_name: "e2e-playwright-test",
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
    },
    headers: { "Content-Type": "application/json" },
    ignoreHTTPSErrors: true,
  });
  if (!response.ok()) {
    const body = await response.text();
    throw new Error(
      `MCP client registration failed (${response.status()}): ${body}`
    );
  }
  return (await response.json()) as ClientRegistration;
}

// ---------------------------------------------------------------------------
// OAuth authorization + token exchange
// ---------------------------------------------------------------------------

export interface McpTokens {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
}

/**
 * Run the full MCP OAuth 2.1 flow inside a Playwright page:
 *   register → authorize (Keycloak login) → exchange code for tokens.
 *
 * Returns a Bearer access_token that can be used for MCP requests.
 */
export async function acquireMcpToken(
  page: Page,
  user: TestUser
): Promise<{ tokens: McpTokens; client: ClientRegistration }> {
  // 1. Register a dynamic client
  const client = await registerMcpClient(page);

  // 2. PKCE
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = randomBytes(16).toString("hex");

  // 3. Intercept the callback redirect so the browser doesn't try to load it.
  //    We extract the auth code from page.url() after waitForURL resolves.
  await page.route("**/oauth-test-callback*", (route) => {
    route.fulfill({ status: 200, contentType: "text/html", body: "<html><body>callback</body></html>" });
  });

  // 4. Navigate to authorize endpoint — triggers Keycloak login
  const authorizeUrl = new URL(
    buildUrl(mcpUrls.server, mcpPaths.authorize)
  );
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("client_id", client.client_id);
  authorizeUrl.searchParams.set("redirect_uri", CALLBACK_URL);
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("code_challenge", codeChallenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");

  await page.goto(authorizeUrl.toString(), {
    waitUntil: "domcontentloaded",
    timeout: timeouts.long,
  });

  // 5. If we land on Keycloak, complete the login
  const afterGotoUrl = page.url();
  if (afterGotoUrl.includes("keycloak")) {
    const keycloakUsername = getKeycloakUsername(user);
    await page.waitForSelector("#kc-form-login", {
      timeout: timeouts.long,
    });
    await page.getByLabel(/username/i).fill(keycloakUsername);
    await page.getByLabel("Password", { exact: true }).fill(user.password);
    await page.getByRole("button", { name: /sign in/i }).click();

    // After login, wait for the callback redirect
    await page.waitForURL((url) => url.href.includes("oauth-test-callback"), {
      timeout: timeouts.long,
    });
  }

  // 6. Extract the auth code from the final page URL
  const finalUrl = new URL(page.url());
  const authCode = finalUrl.searchParams.get("code");

  if (!authCode) {
    throw new Error(
      `Failed to capture authorization code. Final URL: ${page.url()}`
    );
  }

  // 7. Unroute
  await page.unroute("**/oauth-test-callback*");

  // 8. Exchange code for tokens
  const tokenUrl = buildUrl(mcpUrls.server, mcpPaths.token);
  const tokenResponse = await page.request.post(tokenUrl, {
    form: {
      grant_type: "authorization_code",
      code: authCode,
      redirect_uri: CALLBACK_URL,
      client_id: client.client_id,
      code_verifier: codeVerifier,
    },
    ignoreHTTPSErrors: true,
  });
  if (!tokenResponse.ok()) {
    const body = await tokenResponse.text();
    throw new Error(
      `MCP token exchange failed (${tokenResponse.status()}): ${body}`
    );
  }

  const tokens = (await tokenResponse.json()) as McpTokens;
  return { tokens, client };
}

// ---------------------------------------------------------------------------
// MCP Streamable HTTP helpers
// ---------------------------------------------------------------------------

/**
 * Send a JSON-RPC request to the MCP server via Streamable HTTP,
 * authenticated with a Bearer token.
 */
export async function mcpRequest(
  page: Page,
  token: string,
  body: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
  // The upstream MCP server handles Streamable HTTP at /mcp,
  // so we POST to https://mcp.localhost.pomerium.io:8443/mcp
  const url = buildUrl(mcpUrls.server, "/mcp");
  const response = await page.request.post(url, {
    data: body,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${token}`,
    },
    ignoreHTTPSErrors: true,
  });
  const text = await response.text();
  let parsed: Record<string, unknown>;
  try {
    // Try plain JSON first
    parsed = JSON.parse(text);
  } catch {
    // Fall back to SSE: extract JSON from "data: {...}" lines
    const dataLine = text
      .split("\n")
      .find((line) => line.startsWith("data: "));
    if (dataLine) {
      parsed = JSON.parse(dataLine.slice("data: ".length));
    } else {
      parsed = { _raw: text };
    }
  }
  return { status: response.status(), body: parsed };
}

/** Send an MCP initialize request. */
export async function mcpInitialize(
  page: Page,
  token: string
): Promise<{ status: number; body: Record<string, unknown> }> {
  return mcpRequest(page, token, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "e2e-playwright", version: "1.0.0" },
    },
  });
}

/** Send the initialized notification. */
export async function mcpInitializedNotify(
  page: Page,
  token: string
): Promise<void> {
  await mcpRequest(page, token, {
    jsonrpc: "2.0",
    method: "notifications/initialized",
  });
}

/** Send tools/list and return the response. */
export async function mcpToolsList(
  page: Page,
  token: string
): Promise<{ status: number; body: Record<string, unknown> }> {
  return mcpRequest(page, token, {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
  });
}

/** Call a tool and return the response. */
export async function mcpToolsCall(
  page: Page,
  token: string,
  name: string,
  args: Record<string, unknown>,
  id = 3
): Promise<{ status: number; body: Record<string, unknown> }> {
  return mcpRequest(page, token, {
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name, arguments: args },
  });
}

// ---------------------------------------------------------------------------
// MCP SSE Transport helpers
// ---------------------------------------------------------------------------

export interface SseSessionResult {
  endpointUrl: string | null;
  error?: string;
}

export interface SseRpcResult {
  responses: Record<string, unknown>[];
  error?: string;
}

/**
 * Connect to the MCP SSE endpoint inside the browser via page.evaluate().
 * Uses fetch() with ReadableStream (not EventSource) so we can set the
 * Authorization header.
 *
 * Returns the messages endpoint URL from the "endpoint" SSE event.
 */
export async function mcpSseConnect(
  page: Page,
  token: string
): Promise<SseSessionResult> {
  // Navigate to a real page on the MCP domain so the browser has an active
  // TLS connection (the post-OAuth callback page was route-intercepted and
  // may not have established a real TLS handshake).
  const metadataUrl = buildUrl(mcpUrls.server, mcpPaths.oauthMetadata);
  await page.goto(metadataUrl, { waitUntil: "domcontentloaded", timeout: timeouts.medium });

  const sseUrl = buildUrl(mcpUrls.server, "/sse");
  return page.evaluate(
    async ({ url, bearerToken }) => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      try {
        const response = await fetch(url, {
          headers: {
            Authorization: `Bearer ${bearerToken}`,
            Accept: "text/event-stream",
          },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) {
          clearTimeout(timeout);
          return {
            endpointUrl: null,
            error: `SSE connect failed: ${response.status}`,
          };
        }
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });

          // Look for "event: endpoint\ndata: ..."
          const match = buffer.match(
            /event:\s*endpoint\r?\ndata:\s*([^\r\n]+)/
          );
          if (match) {
            clearTimeout(timeout);
            reader.cancel();
            return { endpointUrl: match[1].trim() };
          }
        }
        clearTimeout(timeout);
        return { endpointUrl: null, error: "SSE stream ended without endpoint event" };
      } catch (e: unknown) {
        clearTimeout(timeout);
        const msg = e instanceof Error ? e.message : String(e);
        return { endpointUrl: null, error: `SSE error: ${msg}` };
      }
    },
    { url: sseUrl, bearerToken: token }
  );
}

/**
 * Run a full SSE session: connect, send JSON-RPC messages, collect responses.
 *
 * Uses page.evaluate() to maintain a single long-lived SSE connection
 * while posting messages to the endpoint and reading responses from the
 * SSE stream.
 */
export async function mcpSseSession(
  page: Page,
  token: string,
  messages: Record<string, unknown>[]
): Promise<SseRpcResult> {
  // Ensure the browser has a real TLS connection to the MCP domain.
  const metadataUrl = buildUrl(mcpUrls.server, mcpPaths.oauthMetadata);
  await page.goto(metadataUrl, { waitUntil: "domcontentloaded", timeout: timeouts.medium });

  const sseUrl = buildUrl(mcpUrls.server, "/sse");
  const baseUrl = mcpUrls.server;
  return page.evaluate(
    async ({ url, base, bearerToken, msgs }) => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000);
      const responses: Record<string, unknown>[] = [];

      try {
        // 1. Open SSE connection
        const sseResp = await fetch(url, {
          headers: {
            Authorization: `Bearer ${bearerToken}`,
            Accept: "text/event-stream",
          },
          signal: controller.signal,
        });
        if (!sseResp.ok || !sseResp.body) {
          clearTimeout(timeoutId);
          return { responses: [], error: `SSE status ${sseResp.status}` };
        }

        const reader = sseResp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let endpointPath: string | null = null;

        // Helper: read SSE events from stream until predicate matches
        async function readUntil(
          pred: (events: { event?: string; data?: string }[]) => boolean
        ): Promise<{ event?: string; data?: string }[]> {
          const parsed: { event?: string; data?: string }[] = [];
          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });

            // Split on double-newline (SSE event boundary)
            const parts = buffer.split(/\r?\n\r?\n/);
            buffer = parts.pop() || "";
            for (const part of parts) {
              if (!part.trim()) continue;
              const ev: { event?: string; data?: string } = {};
              for (const line of part.split(/\r?\n/)) {
                if (line.startsWith("event: ")) ev.event = line.slice(7).trim();
                if (line.startsWith("data: ")) ev.data = line.slice(6);
              }
              parsed.push(ev);
            }
            if (pred(parsed)) break;
          }
          return parsed;
        }

        // 2. Wait for endpoint event
        const initial = await readUntil((evts) =>
          evts.some((e) => e.event === "endpoint")
        );
        const epEvt = initial.find((e) => e.event === "endpoint");
        if (!epEvt?.data) {
          clearTimeout(timeoutId);
          reader.cancel();
          return { responses: [], error: "No endpoint event" };
        }
        endpointPath = epEvt.data.trim();
        const messagesUrl = `${base}${endpointPath}`;

        // 3. Send each message and collect responses
        for (const msg of msgs) {
          await fetch(messagesUrl, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${bearerToken}`,
            },
            body: JSON.stringify(msg),
          });

          // For notifications (no id), skip waiting for response
          if (!("id" in msg)) continue;

          // Read next message event from SSE stream
          const evts = await readUntil((parsed) =>
            parsed.some((e) => e.event === "message" || (!e.event && e.data))
          );
          const dataEvt = evts.find(
            (e) => e.event === "message" || (!e.event && e.data)
          );
          if (dataEvt?.data) {
            try {
              responses.push(JSON.parse(dataEvt.data));
            } catch {
              responses.push({ _raw: dataEvt.data });
            }
          }
        }

        clearTimeout(timeoutId);
        reader.cancel();
        return { responses };
      } catch (e: unknown) {
        clearTimeout(timeoutId);
        const errMsg = e instanceof Error ? e.message : String(e);
        return { responses, error: `SSE session error: ${errMsg}` };
      }
    },
    { url: sseUrl, base: baseUrl, bearerToken: token, msgs: messages }
  );
}
