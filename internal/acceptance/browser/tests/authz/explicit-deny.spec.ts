/**
 * Explicit Deny Policy Tests
 *
 * Priority: P1
 * Validates: deny PPL policy evaluation
 *
 * Test Matrix Reference:
 * | AuthZ | Explicit deny | user bob@example.com | deny user=bob@example.com | 403 | Pomerium logs show deny |
 */

import { test, expect } from "@playwright/test";
import { login, clearAuthState } from "../../helpers/authn-flow.js";
import { testUsers } from "../../fixtures/users.js";
import { urls, testRoutes } from "../../fixtures/test-data.js";

test.describe("Explicit Deny Policy", () => {
  test.beforeEach(async ({ page }) => {
    await clearAuthState(page);
  });

  test("should deny explicitly denied user", async ({ page }) => {
    // Bob is explicitly denied from /deny-bob route
    const user = testUsers.bob;

    // Login
    await login(page, { user });

    // Try to access route that explicitly denies bob
    const response = await page.goto(`${urls.app}${testRoutes.denyBob}`, {
      waitUntil: "domcontentloaded",
    });

    // Should be denied (403)
    expect(response).not.toBeNull();
    expect(response!.status()).toBe(403);

    // Verify it's a Pomerium denial
    const content = await page.content();
    expect(content.toLowerCase()).toMatch(/forbidden|denied|unauthorized/i);
  });

  test("deny rule should take precedence over allow", async ({ page }) => {
    // Bob is authenticated but explicitly denied
    // The policy has: deny bob, then allow authenticated_user
    // Deny should take precedence
    const user = testUsers.bob;

    // Login
    await login(page, { user });

    // Verify bob is authenticated by accessing default route
    const defaultResponse = await page.goto(`${urls.app}${testRoutes.default}`, {
      waitUntil: "domcontentloaded",
    });
    expect(defaultResponse!.status()).toBe(200);

    // But still denied from deny-bob route
    const denyResponse = await page.goto(`${urls.app}${testRoutes.denyBob}`, {
      waitUntil: "domcontentloaded",
    });
    expect(denyResponse!.status()).toBe(403);
  });
});
