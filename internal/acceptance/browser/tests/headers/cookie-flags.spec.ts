/**
 * Cookie Security Flags Tests
 *
 * Priority: P0
 * Validates: HttpOnly, Secure, SameSite cookie attributes
 *
 * Test Matrix Reference:
 * | Cookies | Cookie flags | default | allow authenticated_user | Cookie present | HttpOnly, Secure, SameSite=Lax |
 */

import { test, expect } from "@playwright/test";
import { login, clearAuthState } from "../../helpers/authn-flow.js";
import {
  getSessionCookie,
  getCSRFCookie,
  verifySessionCookieSecurity,
  verifyCSRFCookieSecurity,
} from "../../helpers/cookies.js";
import { testUsers } from "../../fixtures/users.js";

test.describe("Cookie Security Flags", () => {
  test.beforeEach(async ({ page }) => {
    await clearAuthState(page);
  });

  test("session cookie should have all required security properties", async ({ page }) => {
    const user = testUsers.alice;

    // Login to get session cookie
    await login(page, { user });

    // Comprehensive security check - HttpOnly, Secure, SameSite, path
    await verifySessionCookieSecurity(page);
  });

  test("CSRF cookie should have required security properties", async ({ page }) => {
    const user = testUsers.alice;

    // Login to get cookies
    await login(page, { user });

    // Check CSRF cookie exists and has security properties
    const csrfCookie = await getCSRFCookie(page);
    expect(csrfCookie, "CSRF cookie should be set after login").toBeDefined();
    await verifyCSRFCookieSecurity(page);
  });

  test("should set fresh cookies on new login", async ({ page }) => {
    const user = testUsers.alice;

    // First login
    await login(page, { user });
    const firstCookie = await getSessionCookie(page);
    expect(firstCookie).toBeDefined();
    const firstValue = firstCookie!.value;

    // Clear and login again
    await clearAuthState(page);
    await login(page, { user });

    const secondCookie = await getSessionCookie(page);
    expect(secondCookie).toBeDefined();
    const secondValue = secondCookie!.value;

    // Should be a different session
    expect(secondValue, "New login should create new session").not.toBe(firstValue);
  });
});
