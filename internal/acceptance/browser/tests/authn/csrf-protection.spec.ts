/**
 * CSRF/State Protection Tests
 *
 * Priority: P0
 * Validates: State parameter integrity, CSRF cookie validation
 *
 * Test Matrix Reference:
 * | AuthN | State/CSRF tamper | standard | allow authenticated_user | Login rejected | invalid state/CSRF error observed |
 */

import { test, expect } from "@playwright/test";
import { tamperCSRFCookie, removeCSRFCookie } from "../../helpers/csrf.js";
import { getSessionCookie } from "../../helpers/cookies.js";
import { testUsers } from "../../fixtures/users.js";
import { urls, paths } from "../../fixtures/test-data.js";

test.describe("CSRF/State Protection", () => {
  test("should reject callback with missing state parameter", async ({ page }) => {
    // Construct a callback URL without state
    const callbackUrl = new URL(
      `${urls.authenticate}${paths.oauth2Callback}`
    );
    callbackUrl.searchParams.set("code", "fake-auth-code");
    // Deliberately not setting state parameter

    const response = await page.goto(callbackUrl.toString(), {
      waitUntil: "domcontentloaded",
    });

    // Should be rejected with 400 Bad Request
    expect(response).not.toBeNull();
    expect(response!.status()).toBe(400);

    // Should not have session
    const sessionCookie = await getSessionCookie(page);
    expect(sessionCookie).toBeUndefined();
  });

  test("should reject callback with empty state parameter", async ({ page }) => {
    // Construct a callback URL with empty state
    const callbackUrl = new URL(
      `${urls.authenticate}${paths.oauth2Callback}`
    );
    callbackUrl.searchParams.set("code", "fake-auth-code");
    callbackUrl.searchParams.set("state", "");

    const response = await page.goto(callbackUrl.toString(), {
      waitUntil: "domcontentloaded",
    });

    // Should be rejected
    expect(response).not.toBeNull();

    // Should not have session
    const sessionCookie = await getSessionCookie(page);
    expect(sessionCookie).toBeUndefined();
  });

  test("should validate CSRF cookie matches state", async ({ page }) => {
    // This test verifies the CSRF cookie validation mechanism

    // Start auth flow
    await page.goto(urls.app, {
      waitUntil: "domcontentloaded",
    });

    // Wait for Keycloak
    await page.waitForURL((url) => url.toString().includes("keycloak"), {
      timeout: 15000,
    });

    // Get the state parameter before tampering
    const authUrl = new URL(page.url());
    const originalState = authUrl.searchParams.get("state");
    expect(originalState).toBeDefined();

    // Tamper with CSRF cookie
    await tamperCSRFCookie(page);

    // Complete login using accessible selectors
    const user = testUsers.alice;
    await page.getByLabel(/username/i).fill(user.email);
    await page.getByLabel("Password", { exact: true }).fill(user.password);
    await page.getByRole("button", { name: /sign in/i }).click();

    // Wait for response
    await page.waitForLoadState("domcontentloaded");

    // Should fail CSRF validation
    const sessionCookie = await getSessionCookie(page);

    // Check for error indication
    const content = await page.content();
    const hasError =
      content.toLowerCase().includes("csrf") ||
      content.toLowerCase().includes("invalid") ||
      content.toLowerCase().includes("error") ||
      sessionCookie === undefined;

    expect(
      hasError,
      "Tampered CSRF cookie should cause validation failure"
    ).toBe(true);
  });

  test("should reject callback without CSRF cookie", async ({ page }) => {
    // Start auth flow
    await page.goto(urls.app, {
      waitUntil: "domcontentloaded",
    });

    // Wait for Keycloak
    await page.waitForURL((url) => url.toString().includes("keycloak"), {
      timeout: 15000,
    });

    // Remove CSRF cookie before completing login
    await removeCSRFCookie(page);

    // Complete login using accessible selectors
    const user = testUsers.alice;
    await page.getByLabel(/username/i).fill(user.email);
    await page.getByLabel("Password", { exact: true }).fill(user.password);
    await page.getByRole("button", { name: /sign in/i }).click();

    // Wait for response
    await page.waitForLoadState("domcontentloaded");

    // Should fail due to missing CSRF
    const sessionCookie = await getSessionCookie(page);
    const content = await page.content();

    const hasError =
      sessionCookie === undefined ||
      content.toLowerCase().includes("csrf") ||
      content.toLowerCase().includes("error");

    expect(
      hasError,
      "Missing CSRF cookie should cause validation failure"
    ).toBe(true);
  });
});
