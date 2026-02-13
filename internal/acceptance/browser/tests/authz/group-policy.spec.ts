/**
 * Group Policy Tests
 *
 * Priority: P0
 * Validates: groups and claims PPL policy evaluation
 *
 * Test Matrix Reference:
 * | AuthZ | Group + claim | group admins, claim department=engineering | allow group=admins AND claim/department=engineering | 200 |
 * | AuthZ | Group negative | user in contractors | allow group=admins | 403 | Upstream not reached |
 */

import { test, expect } from "@playwright/test";
import { login, clearAuthState } from "../../helpers/authn-flow.js";
import { testUsers } from "../../fixtures/users.js";
import { urls, testRoutes } from "../../fixtures/test-data.js";

test.describe("Group Policy", () => {
  test.beforeEach(async ({ page }) => {
    await clearAuthState(page);
  });

  test("should allow user with matching group", async ({ page }) => {
    // Alice is in admins group
    const user = testUsers.alice;
    expect(user.groups).toContain("/admins");

    // Login
    await login(page, { user });

    // Access group-restricted route
    const response = await page.goto(`${urls.app}${testRoutes.byGroup}`, {
      waitUntil: "domcontentloaded",
    });

    expect(response!.status()).toBe(200);
  });

  test("should deny user without matching group", async ({ page }) => {
    // Charlie is only in engineering, not admins
    const user = testUsers.charlie;
    expect(user.groups).not.toContain("/admins");

    // Login
    await login(page, { user });

    // Try to access admin-only route
    const response = await page.goto(`${urls.app}${testRoutes.byGroup}`, {
      waitUntil: "domcontentloaded",
    });

    // Should be denied - user is authenticated but not authorized
    expect(response!.status()).toBe(403);
  });

  test("should allow user with both group AND claim", async ({ page }) => {
    // Alice is in admins AND has department=engineering
    const user = testUsers.alice;
    expect(user.groups).toContain("/admins");
    expect(user.department).toBe("engineering");

    // Login
    await login(page, { user });

    // Access compound policy route
    const response = await page.goto(`${urls.app}${testRoutes.byGroupClaim}`, {
      waitUntil: "domcontentloaded",
    });

    expect(response!.status()).toBe(200);
  });

  test("should deny user with group but missing claim", async ({ page }) => {
    // Diana is in admins but has department=operations, not engineering
    const user = testUsers.diana;
    expect(user.groups).toContain("/admins");
    expect(user.department).not.toBe("engineering");

    // Login
    await login(page, { user });

    // Try to access compound policy route
    const response = await page.goto(`${urls.app}${testRoutes.byGroupClaim}`, {
      waitUntil: "domcontentloaded",
    });

    // Should be denied - has group but not the required claim
    expect(response!.status()).toBe(403);
  });

  test("should enforce multiple groups requirement", async ({ page }) => {
    // Alice is in both admins AND engineering
    const user = testUsers.alice;
    expect(user.groups).toContain("/admins");
    expect(user.groups).toContain("/engineering");

    // Login
    await login(page, { user });

    // Access route requiring both groups
    const response = await page.goto(`${urls.app}${testRoutes.engineeringAdmins}`, {
      waitUntil: "domcontentloaded",
    });

    expect(response!.status()).toBe(200);
  });

  test("user in wrong group should not reach upstream", async ({ page }) => {
    // Bob should not reach the verify service
    const user = testUsers.bob;

    // Login
    await login(page, { user });

    // Try to access admin-only route
    const response = await page.goto(`${urls.app}${testRoutes.adminsOnly}`, {
      waitUntil: "domcontentloaded",
    });
    expect(response?.status(), "Unauthorized user should receive 403").toBe(403);

    // Verify response is from Pomerium (403 page), not from verify service
    const content = await page.content();
    const isPomeriumDenial =
      content.toLowerCase().includes("forbidden") ||
      content.toLowerCase().includes("denied") ||
      content.toLowerCase().includes("pomerium");

    expect(
      isPomeriumDenial,
      "Denied request should be from Pomerium, not upstream"
    ).toBe(true);

    // A 403 page indicates the request was handled by Pomerium, not upstream
  });
});
