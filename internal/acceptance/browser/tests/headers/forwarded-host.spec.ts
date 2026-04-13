/**
 * X-Forwarded-Host Tests
 *
 * Priority: P1
 * Validates: upstream receives the original host when Pomerium rewrites Host
 *
 * Test Matrix Reference:
 * | Headers | x-forwarded-host | host_rewrite | Upstream host rewritten and original host forwarded |
 * | Headers | preserve host header | preserve_host_header: true | Upstream host remains original |
 */

import { test, expect } from "@playwright/test";
import { login, clearAuthState } from "../../helpers/authn-flow.js";
import { testUsers } from "../../fixtures/users.js";
import { urls, testRoutes } from "../../fixtures/test-data.js";

const expectedOriginalHost = new URL(urls.app).host;
// Mirrors the /auto-host-rewrite acceptance route's upstream in config.yaml.
const autoRewrittenHost = "websocket-server:8080";
const rewrittenHost = "rewritten.example.internal";

async function getRequestInfo(page, route: string) {
  const response = await page.request.get(`${urls.app}${route}`, {
    ignoreHTTPSErrors: true,
    headers: {
      Accept: "application/json",
    },
  });

  expect(response.ok(), `Expected ${route} to return JSON`).toBe(true);
  return response.json();
}

test.describe("X-Forwarded-Host", () => {
  test.beforeEach(async ({ page }) => {
    await clearAuthState(page);
  });

  test("should append x-forwarded-host when host rewrite is active", async ({ page }) => {
    await login(page, { user: testUsers.alice });

    const response = await getRequestInfo(page, testRoutes.hostRewrite);

    expect(response.host, "Upstream host should be rewritten").toBe(rewrittenHost);
    expect(
      response.headers["x-forwarded-host"],
      "X-Forwarded-Host should contain the original downstream host"
    ).toContain(expectedOriginalHost);
    expect(
      response.headers["x-forwarded-host"],
      "X-Forwarded-Host should not contain the rewritten upstream host"
    ).not.toContain(rewrittenHost);
  });

  test("should append x-forwarded-host when default auto host rewrite is active", async ({
    page,
  }) => {
    await login(page, { user: testUsers.alice });

    const response = await getRequestInfo(page, testRoutes.autoHostRewrite);

    expect(response.host, "Upstream host should be auto-rewritten to the upstream host").toBe(
      autoRewrittenHost
    );
    expect(
      response.headers["x-forwarded-host"],
      "X-Forwarded-Host should contain the original downstream host"
    ).toContain(expectedOriginalHost);
  });

  test("should preserve the original host when preserve_host_header is enabled", async ({
    page,
  }) => {
    await login(page, { user: testUsers.alice });

    const response = await getRequestInfo(page, testRoutes.hostRewritePreserve);

    expect(response.host, "Upstream should see the original host").toBe(
      expectedOriginalHost
    );
    expect(
      response.headers["x-forwarded-host"],
      "X-Forwarded-Host should not be added when preserve_host_header is enabled"
    ).toBeUndefined();
  });

  test("should allow removing x-forwarded-host after host rewrite", async ({ page }) => {
    await login(page, { user: testUsers.alice });

    const response = await getRequestInfo(page, testRoutes.hostRewriteNoXFH);

    expect(response.host, "Upstream host should still be rewritten").toBe(rewrittenHost);
    expect(
      response.headers["x-forwarded-host"],
      "X-Forwarded-Host should be removed before the upstream request"
    ).toBeUndefined();
  });
});
