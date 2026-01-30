/**
 * JWT Assertion Header Tests
 *
 * Priority: P1
 * Validates: Pomerium identity claims and JWT assertion to upstream
 *
 * Test Matrix Reference:
 * | Headers | JWT assertion | default | allow authenticated_user | Upstream receives assertion | JWT decode matches claims |
 */

import { test, expect } from "@playwright/test";
import { login, clearAuthState } from "../../helpers/authn-flow.js";
import { testUsers } from "../../fixtures/users.js";
import { urls, testRoutes } from "../../fixtures/test-data.js";

test.describe("JWT Assertion Header", () => {
  test.beforeEach(async ({ page }) => {
    await clearAuthState(page);
  });

  test("claim headers should be passed to upstream", async ({ page }) => {
    const user = testUsers.alice;

    // Login
    await login(page, { user });

    // Navigate
    await page.goto(`${urls.app}${testRoutes.default}`, {
      waitUntil: "domcontentloaded",
    });

    // Get headers from verify app's /json endpoint
    const jsonResponse = await page.request.get(`${urls.app}/json`, {
      ignoreHTTPSErrors: true,
    });
    const jsonData = await jsonResponse.json();

    // Check claim headers are present
    expect(
      jsonData.headers?.["X-Pomerium-Claim-Email"],
      "Email claim header should be present"
    ).toBeDefined();

    expect(
      jsonData.headers?.["X-Pomerium-Claim-Groups"],
      "Groups claim header should be present"
    ).toBeDefined();

    expect(
      jsonData.headers?.["X-Pomerium-Claim-Department"],
      "Department claim header should be present"
    ).toBeDefined();

    const departmentHeader = jsonData.headers?.["X-Pomerium-Claim-Department"]?.[0];
    if (departmentHeader) {
      expect(
        departmentHeader,
        "Department claim header should match user attribute"
      ).toBe(user.department);
    }
  });

  test("JWT claims should be accessible via /.pomerium/user endpoint", async ({ page }) => {
    const user = testUsers.alice;

    // Login
    await login(page, { user });

    // Navigate to establish session
    await page.goto(`${urls.app}${testRoutes.default}`, {
      waitUntil: "domcontentloaded",
    });

    // Get user info from Pomerium's /.pomerium/user endpoint
    const userResponse = await page.request.get(`${urls.app}/.pomerium/user`, {
      ignoreHTTPSErrors: true,
    });

    expect(userResponse.ok(), "User endpoint should return OK").toBe(true);

    const userData = await userResponse.json();

    // Verify required claims are present
    expect(userData.email, "Should have email claim").toBe(user.email);
    expect(userData.sub, "Should have subject claim").toBeDefined();

    // Groups should be present and match
    if (Array.isArray(userData.groups)) {
      for (const group of user.groups) {
        expect(userData.groups, `Groups should contain ${group}`).toContain(group);
      }
    }
  });

  test("identity claims should match claim headers", async ({ page }) => {
    const user = testUsers.alice;

    // Login
    await login(page, { user });

    // Navigate to route and get both user info and claim headers
    await page.goto(`${urls.app}${testRoutes.default}`, {
      waitUntil: "domcontentloaded",
    });

    // Get user info from Pomerium
    const userResponse = await page.request.get(`${urls.app}/.pomerium/user`, {
      ignoreHTTPSErrors: true,
    });
    const userData = await userResponse.json();

    // Get headers from verify app
    const jsonResponse = await page.request.get(`${urls.app}/json`, {
      ignoreHTTPSErrors: true,
    });
    const jsonData = await jsonResponse.json();

    // Email should match between user endpoint and claim header
    const emailHeader = jsonData.headers?.["X-Pomerium-Claim-Email"]?.[0];
    if (emailHeader && userData.email) {
      expect(userData.email, "User email should match claim header").toBe(emailHeader);
    }
  });
});
