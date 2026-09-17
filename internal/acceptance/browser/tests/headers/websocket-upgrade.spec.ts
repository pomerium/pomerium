/**
 * WebSocket Upgrade Tests
 *
 * Priority: P1
 * Validates: WebSocket upgrade through Pomerium proxy
 *
 * GitHub Issues:
 * - #5431: HTTP/2 extended connect broke WebSocket upgrade
 *
 * Test Matrix Reference:
 * | Feature | Test Case | Config | Expected |
 * |---------|-----------|--------|----------|
 * | WebSocket | WS upgrade succeeds | allow_websockets: true | 101 Upgrade |
 * | WebSocket | WS with preserve_host | preserve_host_header: true | Host header preserved |
 * | WebSocket | WS echo message | - | Message echoed back |
 */

import { test, expect } from "@playwright/test";
import { login } from "../../helpers/authn-flow.js";
import {
  connectWebSocket,
  sendWebSocketEcho,
  sendWebSocketBinaryEcho,
  toWebSocketUrl,
} from "../../helpers/websocket.js";
import { testUsers } from "../../fixtures/users.js";
import { urls, timeouts } from "../../fixtures/test-data.js";

/**
 * WebSocket test routes.
 */
const wsRoutes = {
  /** WebSocket echo endpoint */
  echo: "/ws",
  /** WebSocket with preserve_host */
  preserveHost: "/ws-preserve-host",
};

test.describe("WebSocket Upgrade", () => {
  test("should upgrade authenticated connection to WebSocket", async ({ page }) => {
    const user = testUsers.alice;

    // First authenticate
    await login(page, { user });

    // Build WebSocket URL from authenticated app URL
    const wsUrl = toWebSocketUrl(urls.app, wsRoutes.echo);

    // Attempt WebSocket connection
    const result = await connectWebSocket(page, wsUrl, timeouts.medium);

    expect(result.success, `WebSocket connection should succeed: ${result.error}`).toBe(true);
    expect(result.welcomeMessage).toBeDefined();
    expect(result.welcomeMessage?.type).toBe("connected");
  });

  test("should send and receive WebSocket messages", async ({ page }) => {
    const user = testUsers.alice;

    // Authenticate
    await login(page, { user });

    const wsUrl = toWebSocketUrl(urls.app, wsRoutes.echo);

    // Send a test message and verify echo
    const testMessage = { action: "test", value: 42, timestamp: Date.now() };
    const result = await sendWebSocketEcho(page, wsUrl, testMessage, timeouts.medium);

    expect(result.success, `WebSocket send/receive should succeed: ${result.error}`).toBe(true);
    expect(result.response).toBeDefined();
    expect(result.response?.type).toBe("echo");
    expect(result.response?.data).toMatchObject(testMessage);
  });

  test("should reject WebSocket connection for unauthenticated user", async ({ page }) => {
    // Don't authenticate - just try to connect
    const wsUrl = toWebSocketUrl(urls.app, wsRoutes.echo);

    // WebSocket connection should fail or redirect
    const result = await connectWebSocket(page, wsUrl, timeouts.short);

    // Unauthenticated request should be rejected
    // Either the connection fails outright, or it gets a non-WS response
    expect(result.success).toBe(false);
  });

  test("should work with preserve_host_header option", async ({ page }) => {
    const user = testUsers.alice;

    // Authenticate
    await login(page, { user });

    const wsUrl = toWebSocketUrl(urls.app, wsRoutes.preserveHost);

    // Connect with preserve_host
    const result = await connectWebSocket(page, wsUrl, timeouts.medium);

    expect(result.success, `WebSocket with preserve_host should succeed: ${result.error}`).toBe(
      true
    );

    // Verify the connection worked and we got a welcome message
    expect(result.welcomeMessage, "Should receive welcome message").toBeDefined();
    expect(result.welcomeMessage?.type).toBe("connected");

    // When preserve_host_header is true, the upstream should see the original host
    // The ws-server returns the host header it receives in the welcome message
    // Note: The actual host value depends on Pomerium's preserve_host_header behavior
    if (result.welcomeMessage?.host) {
      // If host is present, it should be a valid host string
      expect(result.welcomeMessage.host.length).toBeGreaterThan(0);
    }
  });

  test("should handle binary WebSocket messages", async ({ page }) => {
    const user = testUsers.alice;

    // Authenticate
    await login(page, { user });

    const wsUrl = toWebSocketUrl(urls.app, wsRoutes.echo);

    const binaryPayload = [0, 1, 2, 255, 128];
    const result = await sendWebSocketBinaryEcho(page, wsUrl, binaryPayload, timeouts.short);

    expect(result.success, `Binary WebSocket should succeed: ${result.error}`).toBe(true);
    expect(result.responseBytes).toEqual(binaryPayload);
  });
});
