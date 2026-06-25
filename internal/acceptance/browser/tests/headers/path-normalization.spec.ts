/**
 * Path and Header Normalization Tests
 *
 * Priority: P1
 * Validates the default Envoy listener-level normalization behavior that
 * Pomerium configures:
 *   - merge_slashes: true (adjacent slashes are merged before routing)
 *   - path_with_escaped_slashes_action: REJECT_REQUEST (400 on %2F / %5C)
 *   - headers_with_underscores_action: REJECT_REQUEST (400 on header names
 *     containing "_")
 */

import { test, expect } from "@playwright/test";
import { urls } from "../../fixtures/test-data.js";

/** Public echo route configured in pomerium/config.yaml. */
const echoRoute = "/echo";

test.describe("Path and Header Normalization", () => {
  test("should merge adjacent slashes in URL before forwarding upstream", async ({
    request,
  }) => {
    const response = await request.get(`${urls.app}${echoRoute}//foo//bar`, {
      headers: { Accept: "application/json" },
    });

    expect(response.status()).toBe(200);
    const data = await response.json();
    expect(
      data.path,
      "Upstream should observe the merged-slash path"
    ).toBe(`${echoRoute}/foo/bar`);
  });

  test("should reject request whose path contains an escaped slash", async ({
    request,
  }) => {
    const response = await request.get(`${urls.app}${echoRoute}/an%2Fexample`);

    expect(response.status()).toBe(400);
  });

  test("should reject request whose path contains an escaped backslash", async ({
    request,
  }) => {
    const response = await request.get(`${urls.app}${echoRoute}/an%5Cexample`);

    expect(response.status()).toBe(400);
  });

  test("should reject request with a header name containing an underscore", async ({
    request,
  }) => {
    const response = await request.get(`${urls.app}${echoRoute}`, {
      headers: { X_Custom_Header: "value" },
    });

    expect(response.status()).toBe(400);
  });
});
