/**
 * Upstream TLS: tls_upstream_allow_renegotiation.
 * Test plan: Core.Upstream TLS (server-initiated TLS renegotiation).
 *
 * The reneg upstream (Node echo, pinned to TLS 1.2) triggers a server-initiated
 * renegotiation when the path is /reneg, and reports renegotiated: true only
 * after that second handshake completes. Envoy (Pomerium's upstream client)
 * accepts the mid-connection HelloRequest only when the route sets
 * tls_upstream_allow_renegotiation: true; otherwise it terminates the
 * connection, surfaced to the browser as the branded 503 error page. A plain
 * request ("/") never renegotiates and always loads. (The renegotiation is on
 * the Pomerium->upstream hop; the browser is unaffected.)
 */

import { expect, test } from "@playwright/test";
import {
  openRoute,
  pomeriumErrorData,
  UPSTREAM_TERMINATED,
  type EchoJson,
} from "../helpers/routes.js";

test.describe("Upstream TLS: renegotiation", () => {
  test("allow_renegotiation unset: a normal request loads (200, TLS 1.2)", async ({ page }) => {
    // Route: https://reneg-off.localhost.pomerium.io:8443 -> https://upstream-reneg:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt), no renegotiation option

    const resp = await test.step("signed-in user opens the route ('/', no renegotiation) in the browser", () =>
      openRoute(page, "renegOff", "/"));

    const echo = await test.step("page loads (200): a plain request needs no renegotiation", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(200);
      return (await resp!.json()) as EchoJson;
    });

    await test.step("upstream echo confirms TLS 1.2 and that no renegotiation happened", () => {
      expect(echo.tls.protocol).toBe("TLSv1.2");
      expect(echo.renegotiated, "a normal request does not renegotiate").toBe(false);
    });
  });

  test("allow_renegotiation: true: a normal request loads (200)", async ({ page }) => {
    // Route: https://reneg-on.localhost.pomerium.io:8443 -> https://upstream-reneg:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt),
    //         tls_upstream_allow_renegotiation = true

    const resp = await test.step("signed-in user opens the route ('/', no renegotiation) in the browser", () =>
      openRoute(page, "renegOn", "/"));

    const echo = await test.step("page loads (200): allowing renegotiation doesn't affect plain requests", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(200);
      return (await resp!.json()) as EchoJson;
    });

    await test.step("upstream echo confirms TLS 1.2 and that no renegotiation happened", () => {
      expect(echo.tls.protocol).toBe("TLSv1.2");
      expect(echo.renegotiated, "a normal request does not renegotiate").toBe(false);
    });
  });

  test("default: server-initiated renegotiation is refused (503)", async ({ page }) => {
    // Route: https://reneg-off.localhost.pomerium.io:8443 -> https://upstream-reneg:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt), no renegotiation option -
    //         GET /reneg makes the upstream renegotiate mid-connection, which
    //         Envoy refuses by default

    const resp = await test.step("signed-in user opens /reneg (upstream renegotiates mid-request)", () =>
      openRoute(page, "renegOff", "/reneg"));

    await test.step("Envoy refuses the mid-connection renegotiation -> browser gets 503", () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(503);
    });

    await test.step('user sees the branded "Web Server is down" error page with Envoy termination diagnostics', async () => {
      await expect(page.locator("body")).toContainText(UPSTREAM_TERMINATED.pageText);
      const data = await pomeriumErrorData(page);
      expect(data?.statusText ?? "", "Envoy statusText (%RESPONSE_CODE_DETAILS%)").toMatch(
        UPSTREAM_TERMINATED.statusText,
      );
      expect(data?.responseFlags ?? "", "Envoy responseFlags").toMatch(UPSTREAM_TERMINATED.responseFlags);
    });
  });

  test("tls_upstream_allow_renegotiation: true permits renegotiation (200)", async ({ page }) => {
    // Route: https://reneg-on.localhost.pomerium.io:8443 -> https://upstream-reneg:4433
    // Config: tls_custom_ca = base64(upstream-ca.crt),
    //         tls_upstream_allow_renegotiation = true - GET /reneg makes the
    //         upstream renegotiate mid-connection, which Envoy now accepts

    const resp = await test.step("signed-in user opens /reneg (upstream renegotiates mid-request)", () =>
      openRoute(page, "renegOn", "/reneg"));

    const echo = await test.step("page loads (200): Envoy accepted the renegotiation", async () => {
      expect(resp, "navigation produced a response").not.toBeNull();
      expect(resp!.status()).toBe(200);
      return (await resp!.json()) as EchoJson;
    });

    await test.step("upstream echo confirms the second handshake really completed (TLS 1.2)", () => {
      expect(echo.renegotiated, "server-initiated renegotiation completed").toBe(true);
      expect(echo.tls.protocol).toBe("TLSv1.2");
    });
  });
});
