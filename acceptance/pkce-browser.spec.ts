import { test, expect } from "@playwright/test";
import * as crypto from "crypto";
import * as http from "http";

const REALM = process.env.KEYCLOAK_REALM || "pomerium";
const CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || "pomerium";
const CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET || "pomerium-secret";
const USERNAME = process.env.KEYCLOAK_USERNAME || "testuser";
const PASSWORD = process.env.KEYCLOAK_PASSWORD || "testpassword";
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || "http://localhost:8080";
const CALLBACK_PORT = 5555;
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}/callback`;

function generateVerifier(): string {
  return crypto.randomBytes(32).toString("base64url");
}

function computeS256Challenge(verifier: string): string {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

function buildAuthURL(verifier: string, state: string): string {
  const challenge = computeS256Challenge(verifier);
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid profile email",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  return `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/auth?${params}`;
}

async function exchangeCode(
  code: string,
  verifier: string,
): Promise<Record<string, unknown>> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
  });

  const resp = await fetch(
    `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    },
  );

  return (await resp.json()) as Record<string, unknown>;
}

/**
 * Starts a temporary HTTP server that captures the OAuth callback.
 * Returns a promise that resolves with the callback URL when hit.
 */
function startCallbackServer(): {
  server: http.Server;
  waitForCallback: () => Promise<URL>;
} {
  let resolve: (url: URL) => void;
  const promise = new Promise<URL>((r) => {
    resolve = r;
  });

  const server = http.createServer((req, res) => {
    const url = new URL(req.url!, `http://localhost:${CALLBACK_PORT}`);
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("OK");
    resolve(url);
  });

  server.listen(CALLBACK_PORT);

  return {
    server,
    waitForCallback: () => promise,
  };
}

test.describe("PKCE Browser Flow", () => {
  test("single tab: login and exchange code with S256 verifier", async ({
    page,
  }) => {
    const { server, waitForCallback } = startCallbackServer();

    try {
      const verifier = generateVerifier();
      const state = "browser-test-state";
      const authURL = buildAuthURL(verifier, state);

      // Navigate to Keycloak login
      await page.goto(authURL);
      await expect(
        page.getByRole("textbox", { name: "Username or email" }),
      ).toBeVisible();

      // Fill credentials and submit
      await page
        .getByRole("textbox", { name: "Username or email" })
        .fill(USERNAME);
      await page.getByRole("textbox", { name: "Password" }).fill(PASSWORD);
      await page.getByRole("button", { name: "Sign In" }).click();

      // Wait for redirect to hit our callback server
      const callbackURL = await waitForCallback();

      // Verify callback contains code and correct state
      expect(callbackURL.searchParams.get("state")).toBe(state);
      const code = callbackURL.searchParams.get("code");
      expect(code).toBeTruthy();

      // Exchange code with PKCE verifier
      const tokenResponse = await exchangeCode(code!, verifier);
      expect(tokenResponse.access_token).toBeTruthy();
      expect(tokenResponse.id_token).toBeTruthy();
      expect(tokenResponse.token_type).toBe("Bearer");
    } finally {
      server.close();
    }
  });

  test("wrong verifier: token exchange fails", async ({ page }) => {
    const { server, waitForCallback } = startCallbackServer();

    try {
      const verifier = generateVerifier();
      const wrongVerifier = generateVerifier();
      const state = "wrong-verifier-state";
      const authURL = buildAuthURL(verifier, state);

      await page.goto(authURL);
      await page
        .getByRole("textbox", { name: "Username or email" })
        .fill(USERNAME);
      await page.getByRole("textbox", { name: "Password" }).fill(PASSWORD);
      await page.getByRole("button", { name: "Sign In" }).click();

      const callbackURL = await waitForCallback();
      const code = callbackURL.searchParams.get("code");
      expect(code).toBeTruthy();

      // Exchange with WRONG verifier — must fail
      const tokenResponse = await exchangeCode(code!, wrongVerifier);
      expect(tokenResponse.error).toBe("invalid_grant");
    } finally {
      server.close();
    }
  });

  test("multi-tab: two concurrent flows complete independently", async ({
    browser,
  }) => {
    const tabs = [
      { verifier: generateVerifier(), state: "tab-0", code: "" },
      { verifier: generateVerifier(), state: "tab-1", code: "" },
    ];

    // Run each tab flow sequentially (each needs the callback server)
    for (const tab of tabs) {
      const { server, waitForCallback } = startCallbackServer();
      try {
        const context = await browser.newContext();
        const page = await context.newPage();

        const authURL = buildAuthURL(tab.verifier, tab.state);
        await page.goto(authURL);
        await page
          .getByRole("textbox", { name: "Username or email" })
          .fill(USERNAME);
        await page.getByRole("textbox", { name: "Password" }).fill(PASSWORD);
        await page.getByRole("button", { name: "Sign In" }).click();

        const callbackURL = await waitForCallback();
        tab.code = callbackURL.searchParams.get("code") || "";
        expect(tab.code).toBeTruthy();

        await context.close();
      } finally {
        server.close();
      }
    }

    // Exchange codes in reverse order (tab 1 first, then tab 0)
    for (let i = tabs.length - 1; i >= 0; i--) {
      const tab = tabs[i];
      const tokenResponse = await exchangeCode(tab.code, tab.verifier);
      expect(
        tokenResponse.access_token,
        `tab ${i} should get access_token`,
      ).toBeTruthy();
      expect(
        tokenResponse.id_token,
        `tab ${i} should get id_token`,
      ).toBeTruthy();
    }
  });
});
