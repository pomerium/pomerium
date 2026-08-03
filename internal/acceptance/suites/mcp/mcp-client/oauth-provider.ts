// A minimal in-memory OAuthClientProvider for the MCP TypeScript SDK.
//
// The SDK drives the whole OAuth 2.1 flow (discovery, Dynamic Client
// Registration, PKCE, token exchange) and calls into this provider to persist
// state and to hand us the authorization URL. Instead of actually redirecting a
// user agent, `redirectToAuthorization` just records the URL so the test harness
// can drive it with Playwright (see connect.ts).

import type { OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import type {
  OAuthClientInformationFull,
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { CLIENT_NAME } from "./constants.js";

export class InMemoryOAuthProvider implements OAuthClientProvider {
  /** Set by redirectToAuthorization — the URL the "user agent" should visit. */
  authorizationUrl?: URL;

  private _clientInformation?: OAuthClientInformationMixed;
  private _tokens?: OAuthTokens;
  private _codeVerifier?: string;
  private readonly _redirectUrl: string;
  private readonly _clientMetadata: OAuthClientMetadata;

  constructor(redirectUrl: string) {
    this._redirectUrl = redirectUrl;
    this._clientMetadata = {
      client_name: CLIENT_NAME,
      redirect_uris: [redirectUrl],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      // Public (native/loopback) client using PKCE — no client secret.
      token_endpoint_auth_method: "none",
    };
  }

  get redirectUrl(): string {
    return this._redirectUrl;
  }

  get clientMetadata(): OAuthClientMetadata {
    return this._clientMetadata;
  }

  clientInformation(): OAuthClientInformationMixed | undefined {
    return this._clientInformation;
  }

  saveClientInformation(info: OAuthClientInformationFull): void {
    this._clientInformation = info;
  }

  tokens(): OAuthTokens | undefined {
    return this._tokens;
  }

  saveTokens(tokens: OAuthTokens): void {
    this._tokens = tokens;
  }

  redirectToAuthorization(authorizationUrl: URL): void {
    this.authorizationUrl = authorizationUrl;
  }

  saveCodeVerifier(codeVerifier: string): void {
    this._codeVerifier = codeVerifier;
  }

  codeVerifier(): string {
    if (!this._codeVerifier) {
      throw new Error("no PKCE code verifier has been saved");
    }
    return this._codeVerifier;
  }
}
