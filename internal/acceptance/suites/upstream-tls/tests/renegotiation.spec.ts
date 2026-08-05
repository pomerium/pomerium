/**
 * Upstream TLS: tls_upstream_allow_renegotiation.
 * Test plan: Core.Upstream TLS (server-initiated TLS renegotiation).
 *
 * The reneg upstream (Node echo, pinned to TLS 1.2) triggers a server-initiated
 * renegotiation when the path is /reneg. Envoy (Pomerium's upstream client)
 * accepts the mid-connection HelloRequest only when the route sets
 * tls_upstream_allow_renegotiation: true; otherwise it resets, surfaced to the
 * browser as a 503. A plain request ("/") never renegotiates and always loads.
 * (The renegotiation is on the Pomerium->upstream hop; the browser is unaffected.)
 */

import { expect, test } from "@playwright/test";
import { expectHandshake503, gotoEcho } from "../helpers/routes.js";

test.describe("Upstream TLS: renegotiation", () => {
  test("allow_renegotiation unset: a normal request loads (200, TLS 1.2)", async ({ page }) => {
    const echo = await gotoEcho(page, "renegOff", "/");
    expect(echo.tls.protocol).toBe("TLSv1.2");
  });

  test("allow_renegotiation: true: a normal request loads (200)", async ({ page }) => {
    await gotoEcho(page, "renegOn", "/");
  });

  test("default: server-initiated renegotiation is refused (503)", async ({ page }) => {
    await expectHandshake503(page, "renegOff", "/reneg");
  });

  test("tls_upstream_allow_renegotiation: true permits renegotiation (200)", async ({ page }) => {
    const echo = await gotoEcho(page, "renegOn", "/reneg");
    expect(echo.tls.protocol).toBe("TLSv1.2");
  });
});
