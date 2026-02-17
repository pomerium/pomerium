/**
 * Auth Code Flow Login Tests
 *
 * Priority: P0
 * Validates: OIDC auth code flow with Keycloak, session cookie creation
 *
 * Test Matrix Reference:
 * | AuthN | Auth code login (state/CSRF) | standard | allow authenticated_user | 200, session cookie set |
 */

import { test, expect } from "@playwright/test";
import { login, clearAuthState, isLoggedIn } from "../../helpers/authn-flow.js";
import { getSessionCookie } from "../../helpers/cookies.js";
import { testUsers } from "../../fixtures/users.js";
import { urls } from "../../fixtures/test-data.js";

test.describe("Auth Code Flow Login", () => {
  test.beforeEach(async ({ page }) => {
    // Clear any existing auth state
    await clearAuthState(page);
  });

  test("should redirect unauthenticated user to Keycloak login", async ({ page }) => {
    // Navigate to protected resource
    await page.goto(urls.app, {
      waitUntil: "domcontentloaded",
    });

    // Should be redirected to Keycloak
    await page.waitForURL((url) => url.toString().includes("keycloak"), {
      timeout: 15000,
    });

    const currentUrl = page.url();
    expect(currentUrl).toContain("keycloak.localhost.pomerium.io");
    expect(currentUrl).toContain("/realms/pomerium-e2e/protocol/openid-connect/auth");

    // Verify OAuth parameters are present
    const url = new URL(currentUrl);
    expect(url.searchParams.get("client_id")).toBe("pomerium");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("redirect_uri")).toContain("oauth2/callback");
    expect(url.searchParams.get("scope")).toContain("openid");
    expect(url.searchParams.get("state")).toBeTruthy();
  });

  test("should complete login flow and set session cookie", async ({ page }) => {
    const user = testUsers.alice;

    // Perform login
    await login(page, { user });

    // Verify we're back at the app
    const currentUrl = page.url();
    expect(currentUrl).toContain("app.localhost.pomerium.io");

    // Verify session cookie is set
    const sessionCookie = await getSessionCookie(page);
    expect(sessionCookie, "Session cookie should be set").toBeDefined();
    expect(sessionCookie!.value.length).toBeGreaterThan(0);

    // Verify user is logged in
    expect(await isLoggedIn(page)).toBe(true);
  });


  test("should preserve target URL after login redirect", async ({ page }) => {
    const user = testUsers.alice;
    const targetPath = "/by-group";

    // Navigate to specific protected path
    await page.goto(`${urls.app}${targetPath}`, {
      waitUntil: "domcontentloaded",
    });

    // Should redirect to Keycloak
    await page.waitForURL((url) => url.toString().includes("keycloak"), {
      timeout: 15000,
    });

    // Complete login using accessible selectors
    await page.getByLabel(/username/i).fill(user.email);
    await page.getByLabel("Password", { exact: true }).fill(user.password);
    await page.getByRole("button", { name: /sign in/i }).click();

    // Should return to original target path
    await page.waitForURL((url) => {
      // Use proper URL hostname parsing for security
      return (
        url.hostname === "app.localhost.pomerium.io" &&
        url.pathname.includes(targetPath)
      );
    }, { timeout: 15000 });
  });


  test("should request correct OIDC scopes", async ({ page }) => {
    // Navigate to trigger OAuth redirect
    await page.goto(urls.app, {
      waitUntil: "domcontentloaded",
    });

    // Wait for redirect to Keycloak
    await page.waitForURL((url) => url.toString().includes("keycloak"), {
      timeout: 15000,
    });

    const url = new URL(page.url());
    const scope = url.searchParams.get("scope");

    expect(scope, "Scope should be present").toBeDefined();

    // Verify required scopes are requested
    const scopes = scope!.split(" ");
    expect(scopes).toContain("openid");
    expect(scopes).toContain("profile");
    expect(scopes).toContain("email");
    expect(scopes).toContain("groups");
    expect(scopes).toContain("offline_access");
  });
});
