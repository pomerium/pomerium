/**
 * CORS Preflight Tests
 *
 * Priority: P1
 * Validates: CORS preflight handling with cors_allow_preflight option
 *
 * GitHub Issues:
 * - #409: CORS on authenticate service
 * - #390: CORS XHR calls issue
 *
 * Test Matrix Reference:
 * | Feature | Test Case | Config | Expected |
 * |---------|-----------|--------|----------|
 * | CORS | cors_allow_preflight passes OPTIONS | cors_allow_preflight: true | 200 with CORS headers |
 * | CORS | CORS without option = blocked | no cors_allow_preflight | 302 redirect |
 * | CORS | Public route + CORS | allow_public_unauthenticated_access | 200 |
 */

import { test, expect } from "@playwright/test";
import { sendPreflight, makeCrossOriginRequest, testOrigins } from "../../helpers/cors.js";
import { urls } from "../../fixtures/test-data.js";

/**
 * CORS test routes.
 */
const corsRoutes = {
  /** Route with cors_allow_preflight enabled */
  enabled: "/cors-enabled",
  /** Route without cors_allow_preflight */
  disabled: "/cors-disabled",
  /** Public route with CORS */
  public: "/cors-public",
};

test.describe("CORS Preflight", () => {
  test("should pass OPTIONS preflight with cors_allow_preflight enabled", async ({ page }) => {
    // Send preflight to CORS-enabled route
    const url = `${urls.app}${corsRoutes.enabled}`;
    const result = await sendPreflight(page, url, testOrigins.trusted, "GET");

    // Preflight should succeed (2xx status)
    expect(result.ok, `Preflight should succeed, got status ${result.status}`).toBe(true);

    // Should have CORS headers
    expect(result.allowedOrigin).toBeDefined();
  });

  test("should not allow unauthenticated access even when preflight is enabled", async ({ page }) => {
    await page.goto(urls.corsOrigin);

    const url = `${urls.app}${corsRoutes.enabled}`;

    const result = await makeCrossOriginRequest(page, url, {
      method: "GET",
      headers: { "X-Custom-Header": "cors-auth-check" }, // forces preflight
      credentials: "omit",
    });

    expect(
      result.success,
      "CORS preflight should not bypass authentication requirements"
    ).toBe(false);
  });

  test("should redirect OPTIONS without cors_allow_preflight", async ({ page }) => {
    // Send preflight to route without CORS enabled
    const url = `${urls.app}${corsRoutes.disabled}`;
    const result = await sendPreflight(page, url, testOrigins.trusted, "GET");

    // Without cors_allow_preflight, OPTIONS is treated as a regular request
    // and should trigger auth redirect to the sign_in page.
    // Playwright follows redirects, so we detect via wasRedirected or final URL
    const corsBlocked =
      result.wasRedirected ||
      result.finalUrl.includes("sign_in") ||
      result.finalUrl.includes("authenticate") ||
      !result.allowedOrigin;

    expect(corsBlocked, "OPTIONS should redirect without cors_allow_preflight").toBe(true);
  });

  test("should allow actual cross-origin GET after preflight", async ({ page }) => {
    // Navigate to a different origin to ensure a true CORS request
    await page.goto(urls.corsOrigin);

    const url = `${urls.app}${corsRoutes.public}`;

    // Make actual cross-origin request
    const result = await makeCrossOriginRequest(page, url, {
      method: "GET",
      headers: { "X-Custom-Header": "cors-test" }, // forces preflight
      credentials: "omit",
    });

    // Should succeed if CORS is properly configured
    expect(result.success, `Cross-origin request should succeed: ${result.error}`).toBe(true);
    expect(result.status).toBe(200);
  });

  test("should allow cross-origin POST with cors_allow_preflight", async ({ page }) => {
    await page.goto(urls.corsOrigin);

    const url = `${urls.app}${corsRoutes.public}`;

    // Make POST request
    const result = await makeCrossOriginRequest(page, url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ test: "data" }),
      credentials: "omit",
    });

    // POST should work if CORS is configured
    expect(result.success, `Cross-origin POST should succeed: ${result.error}`).toBe(true);
  });

  test("should block cross-origin request without cors_allow_preflight", async ({ page }) => {
    // Don't authenticate - test that unauthenticated cross-origin requests fail
    // when cors_allow_preflight is not set (preflight requires auth)
    await page.goto(urls.corsOrigin);

    const url = `${urls.app}${corsRoutes.disabled}`;

    // Make a non-simple request that requires preflight
    // POST with application/json Content-Type triggers preflight
    const result = await makeCrossOriginRequest(page, url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ test: "data" }),
      credentials: "omit", // Don't send credentials for this test
    });

    // Without cors_allow_preflight, the OPTIONS preflight requires authentication
    // Since we're not authenticated, the preflight fails and the request is blocked
    const blocked = !result.success || result.error !== undefined;

    expect(blocked, "Request to non-CORS route should be blocked for unauthenticated users").toBe(
      true
    );
  });
});
