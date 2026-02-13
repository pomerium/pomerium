/**
 * Email Domain Policy Tests
 *
 * Priority: P0
 * Validates: email_domain PPL policy evaluation
 *
 * Test Matrix Reference:
 * | AuthZ | Domain allow | user email @company.com | allow email_domain | 200 |
 */

import { test, expect } from "@playwright/test";
import { login, clearAuthState } from "../../helpers/authn-flow.js";
import { testUsers } from "../../fixtures/users.js";
import { urls, testRoutes } from "../../fixtures/test-data.js";

test.describe("Email Domain Policy", () => {
  test.beforeEach(async ({ page }) => {
    await clearAuthState(page);
  });

  test("should allow access for user with matching email domain", async ({ page }) => {
    // Alice has email alice@company.com - should be allowed
    const user = testUsers.alice;

    // Login
    await login(page, { user });

    // Access domain-restricted route
    const response = await page.goto(`${urls.app}${testRoutes.byDomain}`, {
      waitUntil: "domcontentloaded",
    });

    // Should be allowed
    expect(response).not.toBeNull();
    expect(response!.status()).toBe(200);

    // Verify we're at the expected route, not redirected
    expect(page.url()).toContain(testRoutes.byDomain);
  });

  test("should deny access for user with non-matching email domain", async ({ page }) => {
    // Bob has email bob@example.com - should be denied from @company.com route
    const user = testUsers.bob;

    // Login
    await login(page, { user });

    // Try to access domain-restricted route
    const response = await page.goto(`${urls.app}${testRoutes.byDomain}`, {
      waitUntil: "domcontentloaded",
    });

    // Should be denied - user is authenticated but not authorized for this domain
    expect(response).not.toBeNull();
    expect(response!.status()).toBe(403);

    // Verify it's a Pomerium denial page
    const content = await page.content();
    expect(content.toLowerCase()).toMatch(/forbidden|denied|unauthorized/i);
  });

  test("should enforce domain policy independent of groups", async ({ page }) => {
    // Diana is an admin but has @external.org - should still be denied from domain route
    const user = testUsers.diana;
    expect(user.groups).toContain("/admins");
    expect(user.emailDomain).toBe("external.org");

    // Login
    await login(page, { user });

    // Access domain-restricted route
    const response = await page.goto(`${urls.app}${testRoutes.byDomain}`, {
      waitUntil: "domcontentloaded",
    });

    // Should be denied despite being admin - domain policy is independent
    expect(response).not.toBeNull();
    expect(response!.status()).toBe(403);
  });
});
