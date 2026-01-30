/**
 * Logout Tests
 *
 * Priority: P0
 * Validates: HMAC-signed logout URLs, session cookie clearance
 *
 * Pomerium's sign_out uses HMAC-signed URLs (not CSRF tokens):
 * - Proxy creates signed URL with pomerium_signature, pomerium_issued, pomerium_expiry params
 * - Authenticate service validates HMAC signature (5-minute expiry)
 * - Unsigned requests show SignOutConfirm page (not an error)
 *
 * Test Matrix Reference:
 * | AuthN | Logout (HMAC-signed) | standard | allow authenticated_user | Cookie cleared, redirect to login |
 */

import { test, expect } from "@playwright/test";
import { login, clearAuthState } from "../../helpers/authn-flow.js";
import { getSessionCookie, verifySessionCookieAbsent } from "../../helpers/cookies.js";
import { testUsers } from "../../fixtures/users.js";
import { urls, paths } from "../../fixtures/test-data.js";

test.describe("Logout", () => {
  test.beforeEach(async ({ page }) => {
    await clearAuthState(page);
  });

  test("should clear session cookie on logout", async ({ page }) => {
    const user = testUsers.alice;

    // Login first
    await login(page, { user });

    // Verify we have a session
    let sessionCookie = await getSessionCookie(page);
    expect(sessionCookie, "Should have session cookie after login").toBeDefined();

    // Navigate to sign_out - this shows confirmation page with signed URL
    await page.goto(`${urls.app}${paths.signOut}`, {
      waitUntil: "domcontentloaded",
    });

    // Click the Logout button in the confirmation dialog to use the signed URL
    const logoutButton = page.getByRole("button", { name: "Logout" });
    if (await logoutButton.isVisible()) {
      await logoutButton.click();
      await page.waitForLoadState("domcontentloaded");
    }

    // Session cookie should be cleared
    sessionCookie = await getSessionCookie(page);
    expect(
      sessionCookie?.value === "" ||
        sessionCookie?.value === undefined ||
        sessionCookie === undefined,
      "Session cookie should be cleared after logout"
    ).toBe(true);
  });

  test("should require authentication after logout", async ({ page }) => {
    const user = testUsers.alice;

    // Login
    await login(page, { user });

    // Verify access works
    let response = await page.goto(urls.app, {
      waitUntil: "domcontentloaded",
    });
    expect(response!.status()).toBe(200);

    // Logout via confirmation page
    await page.goto(`${urls.app}${paths.signOut}`, {
      waitUntil: "domcontentloaded",
    });

    // Click the Logout button to confirm
    const logoutButton = page.getByRole("button", { name: "Logout" });
    if (await logoutButton.isVisible()) {
      await logoutButton.click();
      await page.waitForLoadState("domcontentloaded");
    }

    // Try to access protected resource
    await page.goto(urls.app, {
      waitUntil: "domcontentloaded",
    });

    // Should redirect to login
    const currentUrl = page.url();
    const requiresAuth =
      currentUrl.includes("keycloak") ||
      currentUrl.includes("sign_in") ||
      currentUrl.includes("authenticate");

    expect(requiresAuth, "Should require re-authentication after logout").toBe(true);
  });

  test("unsigned sign_out redirects to authenticate service", async ({ page }) => {
    const user = testUsers.alice;

    // Login first
    await login(page, { user });

    // Verify we have a session
    const sessionBefore = await getSessionCookie(page);
    expect(sessionBefore).toBeDefined();

    // Request sign_out without following redirects to see what Pomerium does
    const response = await page.request.get(`${urls.app}${paths.signOut}`, {
      ignoreHTTPSErrors: true,
      maxRedirects: 0,
    });

    // Pomerium redirects sign_out to authenticate service with signature
    const status = response.status();
    expect(status, "Unsigned sign_out should redirect").toBe(302);

    const location = response.headers()["location"] || "";
    expect(location, "Should redirect to authenticate service").toContain("authenticate");
    expect(location, "Redirect should include signature").toContain("pomerium_signature");
  });

  test("sign_out flow clears session via confirmation page", async ({ page }) => {
    const user = testUsers.alice;

    // Login
    await login(page, { user });

    // Navigate to sign_out - Pomerium handles this and shows confirmation page
    await page.goto(`${urls.app}${paths.signOut}`, {
      waitUntil: "domcontentloaded",
    });

    // The page should have some form of logout confirmation UI
    // Use getByRole for accessibility-first selectors
    const logoutButton = page
      .getByRole("button", { name: /log\s*out|sign\s*out|confirm/i })
      .or(page.getByRole("link", { name: /log\s*out|sign\s*out|confirm/i }))
      .first();

    // If there's a confirmation button, click it
    if (await logoutButton.isVisible()) {
      await logoutButton.click();
      await page.waitForLoadState("domcontentloaded");
    }

    // After the flow, either redirected or session cleared
    const currentUrl = page.url();
    const sessionAfter = await getSessionCookie(page);

    // Either the session is cleared OR we've been redirected to sign_in/IdP
    const flowComplete =
      sessionAfter === undefined ||
      sessionAfter.value === "" ||
      currentUrl.includes("signed_out") ||
      currentUrl.includes("sign_in") ||
      currentUrl.includes("keycloak");

    expect(flowComplete, "Logout flow should complete").toBe(true);
  });
});
