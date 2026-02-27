/**
 * Token Refresh Tests
 *
 * Priority: P0
 * Validates: Automatic token refresh without user interaction
 *
 * Test Matrix Reference:
 * | Lifecycle | Token refresh | short access token | allow authenticated_user | 200 after expiry | no interactive auth redirect |
 */

import { test, expect } from "@playwright/test";
import { login, isLoggedIn } from "../../helpers/authn-flow.js";
import { getSessionCookie } from "../../helpers/cookies.js";
import { waitForTokenExpiry } from "../../helpers/wait.js";
import { testUsers } from "../../fixtures/users.js";
import { urls } from "../../fixtures/test-data.js";

test.describe("Token Refresh", () => {
  test("should maintain access after token expiry through refresh", async ({ page }) => {
    const user = testUsers.alice;

    // Login
    await login(page, { user });

    // Verify initial access
    let response = await page.goto(urls.app, {
      waitUntil: "domcontentloaded",
    });
    expect(response!.status()).toBe(200);

    // Wait for access token to expire (configured lifespan + buffer)
    await waitForTokenExpiry();

    // Make another request - should still work via token refresh
    response = await page.goto(urls.app, {
      waitUntil: "domcontentloaded",
    });

    // Key assertion: should still get 200, not redirect to login
    expect(response!.status()).toBe(200);

    // Verify we're still at the app, not redirected to Keycloak
    // This is the definitive check - if token refresh failed, we'd be on Keycloak
    const currentUrl = page.url();
    expect(currentUrl).not.toContain("keycloak");
    expect(currentUrl).toContain("app.localhost.pomerium.io");

    // Verify user remains logged in
    expect(await isLoggedIn(page), "Should still be logged in after refresh").toBe(true);
  });

  test("should preserve session cookie after refresh", async ({ page }) => {
    const user = testUsers.alice;

    // Login
    await login(page, { user });

    // Get initial session cookie
    const initialCookie = await getSessionCookie(page);
    expect(initialCookie).toBeDefined();

    // Wait for token expiry
    await waitForTokenExpiry();

    // Make request to trigger refresh
    await page.goto(urls.app, {
      waitUntil: "domcontentloaded",
    });

    // Session cookie should still exist (may have different value)
    const afterRefreshCookie = await getSessionCookie(page);
    expect(
      afterRefreshCookie,
      "Session cookie should exist after refresh"
    ).toBeDefined();
  });
});
