import { test, expect, Cookie } from "@playwright/test";
import { getCookieByName } from "../../helpers/cookies.js";
import { testUsers } from "../../fixtures/users.js";
import { urls } from "../../fixtures/test-data.js";
import { clearAuthState, submitLoginForm, waitForLoginPage } from "@helpers/authn-flow.js";

test.describe("PKCE", () => {
  test("login should set PKCE query parameters", async ({ page }) => {
    // Navigate to protected resource
    await page.goto(urls.app);

    // Should be redirected to Keycloak
    await waitForLoginPage(page);

    // Verify that the PKCE query parameters are present
    const params = new URL(page.url()).searchParams;
    expect(params.get("code_challenge_method")).toBe("S256");
    expect(params.get("code_challenge")).toHaveLength(43);
  });

  test("login should fail with missing PKCE cookie", async ({ page }) => {
    // Navigate to protected resource
    await page.goto(urls.app);

    // Should be redirected to Keycloak
    await waitForLoginPage(page);

    // Remove the browser cookie storing the PKCE state
    await page.context().clearCookies({ name: /pomerium_pkce_.*/ });

    // Complete the IdP login
    await submitLoginForm(page, testUsers.alice);

    // Verify a Pomerium error page shows
    await page.waitForURL((url) => url.toString().includes(urls.authenticate));
    expect(page.getByRole("alert")).toHaveText("400 Bad Request");
  });

  test("login should fail with tampered PKCE cookie", async ({ page }) => {
    // Navigate to protected resource
    await page.goto(urls.app);

    // Should be redirected to Keycloak
    await waitForLoginPage(page);

    // Alter the browser cookie storing the PKCE state
    const cookie = await getCookieByName(page, /pomerium_pkce_.*/) as Cookie;
    expect(cookie).not.toBeUndefined();
    cookie.value = "not-a-valid-pkce-cookie";
    page.context().addCookies([cookie]);

    // Complete the IdP login
    await submitLoginForm(page, testUsers.alice);

    // Verify a Pomerium error page shows
    await page.waitForURL((url) => url.toString().includes(urls.authenticate));
    expect(page.getByRole("alert")).toHaveText("400 Bad Request");
  });

  test("login should fail with replayed PKCE cookie", async ({ page }) => {
    // Capture the PKCE cookie from a successful login flow
    await page.goto(urls.app);
    await waitForLoginPage(page);

    const cookie1 = await getCookieByName(page, /pomerium_pkce_.*/) as Cookie;
    expect(cookie1).not.toBeUndefined();

    await submitLoginForm(page, testUsers.alice);
    await page.waitForURL((url) => url.toString().includes(urls.app));
    expect(page.getByText("Signed Identity Token")).toBeVisible();

    // Now initate a second login flow but replay the previous PKCE cookie
    await clearAuthState(page);
    await page.goto(urls.app);
    await waitForLoginPage(page);

    const cookie2 = await getCookieByName(page, /pomerium_pkce_.*/) as Cookie;
    expect(cookie2).not.toBeUndefined();
    cookie2.value = cookie1.value;
    page.context().addCookies([cookie2]);

    // This login flow should not complete successfully
    await submitLoginForm(page, testUsers.alice);
    await page.waitForURL((url) => url.toString().includes(urls.authenticate));
    expect(page.getByRole("alert")).toHaveText("400 Bad Request");
  });

  test("multiple PKCE cookies can coexist", async ({ context }) => {
    // Start the login flow in two different tabs
    const page1 = await context.newPage();
    await page1.goto(urls.app);
    await waitForLoginPage(page1);

    const page2 = await context.newPage();
    await page2.goto(urls.app);
    await waitForLoginPage(page2);

    // We should have two independent PKCE cookies
    const cookies = (await context.cookies())
      .filter((c) => /pomerium_pkce_.*/.test(c.name));
    expect(cookies).toHaveLength(2);

    // Both login flows should be able to complete successfully
    await submitLoginForm(page1, testUsers.alice);
    await page1.waitForURL((url) => url.toString().includes(urls.app));
    expect(page1.getByText("Signed Identity Token")).toBeVisible();

    await submitLoginForm(page2, testUsers.alice);
    await page2.waitForURL((url) => url.toString().includes(urls.app));
    expect(page2.getByText("Signed Identity Token")).toBeVisible();
  });
});
