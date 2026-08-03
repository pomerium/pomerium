// Raw OAuth 2.1 helpers for endpoint-level and negative tests.
//
// The SDK (connect.ts) is the right tool for happy paths, but spec-conformance
// and security regressions need to poke Pomerium's OAuth endpoints directly and
// inject malformed inputs (empty PKCE, mismatched ports, etc.). These helpers
// build on Playwright's APIRequestContext (which honors use.ignoreHTTPSErrors)
// and drive the interactive browser leg via the reused Keycloak helpers.

import { createHash, randomBytes } from "node:crypto";
import type { APIRequestContext, Page } from "@playwright/test";

import { submitLoginForm, waitForLoginPage } from "./keycloak-login.js";
import type { TestUser } from "../../browser/fixtures/users.js";

export interface ASMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  registration_endpoint?: string;
  response_types_supported?: string[];
  grant_types_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  scopes_supported?: string[];
  code_challenge_methods_supported?: string[];
  client_id_metadata_document_supported?: boolean;
  [k: string]: unknown;
}

export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers?: string[];
  bearer_methods_supported?: string[];
  [k: string]: unknown;
}

/** Generate a PKCE verifier + S256 challenge pair. */
export function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

async function getJSON<T>(request: APIRequestContext, url: string): Promise<T> {
  const res = await request.get(url, { failOnStatusCode: false });
  if (!res.ok()) throw new Error(`GET ${url} -> HTTP ${res.status()}`);
  return (await res.json()) as T;
}

/** Fetch Pomerium's OAuth 2.0 Authorization Server Metadata (RFC 8414). */
export function discoverAS(request: APIRequestContext, origin: string): Promise<ASMetadata> {
  return getJSON<ASMetadata>(request, `${origin}/.well-known/oauth-authorization-server`);
}

/**
 * Fetch and parse Protected Resource Metadata (RFC 9728) from an exact URL —
 * e.g. the `resource_metadata` URI taken from a WWW-Authenticate challenge.
 */
export function fetchResourceMetadata(
  request: APIRequestContext,
  url: string,
): Promise<ProtectedResourceMetadata> {
  return getJSON<ProtectedResourceMetadata>(request, url);
}

/**
 * Discover Protected Resource Metadata (RFC 9728): try the path-scoped
 * well-known URI first, then the root, mirroring the spec's client algorithm.
 */
export async function discoverPRM(
  request: APIRequestContext,
  origin: string,
  path = "/mcp",
): Promise<{ url: string; doc: ProtectedResourceMetadata }> {
  const candidates = [
    `${origin}/.well-known/oauth-protected-resource${path}`,
    `${origin}/.well-known/oauth-protected-resource`,
  ];
  for (const url of candidates) {
    const res = await request.get(url, { failOnStatusCode: false });
    if (res.ok()) return { url, doc: (await res.json()) as ProtectedResourceMetadata };
  }
  throw new Error(`no protected-resource metadata found under ${origin}`);
}

export interface RegisterResult {
  status: number;
  body: Record<string, unknown> | null;
}

/** RFC 7591 Dynamic Client Registration against the AS registration endpoint. */
export async function registerClient(
  request: APIRequestContext,
  registrationEndpoint: string,
  metadata: Record<string, unknown>,
): Promise<RegisterResult> {
  const res = await request.post(registrationEndpoint, {
    headers: { "content-type": "application/json" },
    data: metadata,
    failOnStatusCode: false,
  });
  const body = (await res.json().catch(() => null)) as Record<string, unknown> | null;
  return { status: res.status(), body };
}

export interface AuthorizeOptions {
  page: Page;
  asMeta: ASMetadata;
  clientId: string;
  redirectUri: string;
  user: TestUser;
  /** Awaits the ?code from the loopback callback server. */
  waitForCode: () => Promise<string>;
  /** Omit to send NO code_challenge (PKCE-bypass probe). */
  codeChallenge?: string;
  codeChallengeMethod?: string;
  resource?: string;
  scope?: string;
  state?: string;
}

/**
 * Drive the interactive authorization-code leg in a real browser:
 * open the authorize URL, sign in at Keycloak, and return the captured code.
 * Rejects (via waitForCode) if Pomerium returns an error instead of a code.
 */
export async function authorizeViaBrowser(opts: AuthorizeOptions): Promise<string> {
  const u = new URL(opts.asMeta.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", opts.clientId);
  u.searchParams.set("redirect_uri", opts.redirectUri);
  u.searchParams.set("state", opts.state ?? randomBytes(8).toString("hex"));
  if (opts.scope) u.searchParams.set("scope", opts.scope);
  if (opts.resource) u.searchParams.set("resource", opts.resource);
  if (opts.codeChallenge !== undefined) {
    u.searchParams.set("code_challenge", opts.codeChallenge);
    u.searchParams.set("code_challenge_method", opts.codeChallengeMethod ?? "S256");
  }

  await opts.page.goto(u.toString());
  await waitForLoginPage(opts.page);
  await submitLoginForm(opts.page, opts.user);
  return opts.waitForCode();
}

export interface TokenResult {
  status: number;
  body: Record<string, unknown>;
}

/** Exchange an authorization code at the token endpoint. */
export async function exchangeCode(
  request: APIRequestContext,
  tokenEndpoint: string,
  params: {
    code: string;
    clientId: string;
    redirectUri: string;
    codeVerifier?: string; // omit to probe missing-verifier handling
    resource?: string;
  },
): Promise<TokenResult> {
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
  });
  if (params.codeVerifier !== undefined) form.set("code_verifier", params.codeVerifier);
  if (params.resource) form.set("resource", params.resource);

  const res = await request.post(tokenEndpoint, {
    headers: { "content-type": "application/x-www-form-urlencoded" },
    data: form.toString(),
    failOnStatusCode: false,
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  return { status: res.status(), body };
}

export interface Challenge {
  status: number;
  wwwAuthenticate: string;
  resourceMetadataUrl?: string;
  scope?: string;
}

function wwwParam(header: string, name: string): string | undefined {
  const m = header.match(new RegExp(`${name}="([^"]+)"`, "i"));
  return m?.[1];
}

/**
 * Send an unauthenticated MCP `initialize` to `url` and parse the RFC 9728
 * `WWW-Authenticate` challenge (status, resource_metadata URL, scope).
 */
export async function probeMcp(request: APIRequestContext, url: string): Promise<Challenge> {
  const res = await request.post(url, {
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    data: {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "probe", version: "1.0.0" },
      },
    },
    failOnStatusCode: false,
  });
  const www = res.headers()["www-authenticate"] ?? "";
  return {
    status: res.status(),
    wwwAuthenticate: www,
    resourceMetadataUrl: wwwParam(www, "resource_metadata"),
    scope: wwwParam(www, "scope"),
  };
}

/** Standard public-client (loopback, PKCE) registration metadata. */
export function publicClientMetadata(redirectUri: string, clientName = "pomerium-mcp-e2e-raw") {
  return {
    client_name: clientName,
    redirect_uris: [redirectUri],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  };
}
