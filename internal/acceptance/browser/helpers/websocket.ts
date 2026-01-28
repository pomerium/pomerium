/**
 * WebSocket helpers for E2E acceptance tests.
 * Provides functions to test WebSocket connections through Pomerium.
 */

import { Page } from "@playwright/test";
import { timeouts } from "../fixtures/test-data.js";

/**
 * WebSocket message received from the server.
 */
export interface WSMessage {
  type: string;
  data?: unknown;
  message?: string;
  host?: string;
}

/**
 * Result of a WebSocket connection attempt.
 */
export interface WSConnectionResult {
  success: boolean;
  error?: string;
  welcomeMessage?: WSMessage;
}

/**
 * Result of sending a WebSocket message.
 */
export interface WSSendResult {
  success: boolean;
  error?: string;
  response?: WSMessage;
}

/**
 * Result of sending a binary WebSocket message.
 */
export interface WSSendBinaryResult {
  success: boolean;
  error?: string;
  responseBytes?: number[];
}

/**
 * Connect to a WebSocket endpoint through the page context.
 * This runs in the browser context, so it uses the page's cookies for auth.
 *
 * @param page - Playwright page
 * @param wsUrl - WebSocket URL to connect to
 * @param timeout - Connection timeout in ms
 * @returns Connection result
 */
export async function connectWebSocket(
  page: Page,
  wsUrl: string,
  timeout: number = timeouts.medium
): Promise<WSConnectionResult> {
  return page.evaluate(
    async ({ url, timeout }) => {
      return new Promise<WSConnectionResult>((resolve) => {
        const ws = new WebSocket(url);
        let welcomeMessage: WSMessage | undefined;

        const timeoutId = setTimeout(() => {
          ws.close();
          resolve({ success: false, error: "Connection timeout" });
        }, timeout);

        ws.onopen = () => {
          // Wait briefly for welcome message
          setTimeout(() => {
            clearTimeout(timeoutId);
            resolve({ success: true, welcomeMessage });
          }, 500);
        };

        ws.onmessage = (event) => {
          try {
            welcomeMessage = JSON.parse(event.data);
          } catch {
            welcomeMessage = { type: "raw", data: event.data };
          }
        };

        ws.onerror = () => {
          clearTimeout(timeoutId);
          resolve({ success: false, error: "WebSocket error" });
        };

        ws.onclose = (event) => {
          if (!event.wasClean) {
            clearTimeout(timeoutId);
            resolve({
              success: false,
              error: `Connection closed: code=${event.code}, reason=${event.reason}`,
            });
          }
        };
      });
    },
    { url: wsUrl, timeout }
  );
}

/**
 * Connect to WebSocket and send an echo message, returning the response.
 *
 * @param page - Playwright page
 * @param wsUrl - WebSocket URL to connect to
 * @param message - Message to send
 * @param timeout - Timeout in ms
 * @returns Send result with response
 */
export async function sendWebSocketEcho(
  page: Page,
  wsUrl: string,
  message: string | object,
  timeout: number = timeouts.medium
): Promise<WSSendResult> {
  const messageStr = typeof message === "string" ? message : JSON.stringify(message);

  return page.evaluate(
    async ({ url, msg, timeout }) => {
      return new Promise<WSSendResult>((resolve) => {
        const ws = new WebSocket(url);
        let response: WSMessage | undefined;
        let messageCount = 0;

        const timeoutId = setTimeout(() => {
          ws.close();
          resolve({ success: false, error: "Timeout waiting for echo response" });
        }, timeout);

        ws.onopen = () => {
          // Send the message
          ws.send(msg);
        };

        ws.onmessage = (event) => {
          messageCount++;
          try {
            const parsed = JSON.parse(event.data);
            // Skip welcome message (first message), wait for echo
            if (parsed.type === "echo" || messageCount > 1) {
              response = parsed;
              clearTimeout(timeoutId);
              ws.close();
              resolve({ success: true, response });
            }
          } catch {
            // Non-JSON response
            if (messageCount > 1) {
              response = { type: "raw", data: event.data };
              clearTimeout(timeoutId);
              ws.close();
              resolve({ success: true, response });
            }
          }
        };

        ws.onerror = () => {
          clearTimeout(timeoutId);
          resolve({ success: false, error: "WebSocket error" });
        };

        ws.onclose = (event) => {
          clearTimeout(timeoutId);
          if (!response) {
            resolve({
              success: false,
              error: `Connection closed before response: code=${event.code}`,
            });
          }
        };
      });
    },
    { url: wsUrl, msg: messageStr, timeout }
  );
}

/**
 * Connect to WebSocket and send a binary message, returning the echoed bytes.
 *
 * @param page - Playwright page
 * @param wsUrl - WebSocket URL to connect to
 * @param bytes - Byte payload to send
 * @param timeout - Timeout in ms
 * @returns Send result with echoed bytes
 */
export async function sendWebSocketBinaryEcho(
  page: Page,
  wsUrl: string,
  bytes: number[] | Uint8Array,
  timeout: number = timeouts.medium
): Promise<WSSendBinaryResult> {
  const payload = Array.isArray(bytes) ? bytes : Array.from(bytes);

  return page.evaluate(
    async ({ url, payload, timeout }) => {
      return new Promise<WSSendBinaryResult>((resolve) => {
        const ws = new WebSocket(url);
        ws.binaryType = "arraybuffer";

        const timeoutId = setTimeout(() => {
          ws.close();
          resolve({ success: false, error: "Timeout waiting for binary echo response" });
        }, timeout);

        ws.onopen = () => {
          ws.send(new Uint8Array(payload));
        };

        ws.onmessage = (event) => {
          if (typeof event.data === "string") {
            return;
          }

          const bufferPromise =
            event.data instanceof ArrayBuffer
              ? Promise.resolve(event.data)
              : (event.data as Blob).arrayBuffer();

          bufferPromise
            .then((buffer) => {
              const responseBytes = Array.from(new Uint8Array(buffer));
              clearTimeout(timeoutId);
              ws.close();
              resolve({ success: true, responseBytes });
            })
            .catch(() => {
              clearTimeout(timeoutId);
              ws.close();
              resolve({ success: false, error: "Failed to read binary response" });
            });
        };

        ws.onerror = () => {
          clearTimeout(timeoutId);
          resolve({ success: false, error: "WebSocket error" });
        };

        ws.onclose = (event) => {
          if (event.wasClean) {
            return;
          }
          clearTimeout(timeoutId);
          resolve({
            success: false,
            error: `Connection closed before binary response: code=${event.code}`,
          });
        };
      });
    },
    { url: wsUrl, payload, timeout }
  );
}

/**
 * Test WebSocket connection with message round-trip.
 * Connects, sends a test message, and verifies the echo response.
 *
 * @param page - Playwright page
 * @param wsUrl - WebSocket URL
 * @param timeout - Timeout in ms
 * @returns True if connection and echo succeeded
 */
export async function testWebSocketRoundTrip(
  page: Page,
  wsUrl: string,
  timeout: number = timeouts.medium
): Promise<{ success: boolean; latencyMs?: number; error?: string }> {
  const testMessage = { test: "ping", timestamp: Date.now() };

  const startTime = Date.now();
  const result = await sendWebSocketEcho(page, wsUrl, testMessage, timeout);
  const endTime = Date.now();

  if (!result.success) {
    return { success: false, error: result.error };
  }

  // Verify echo contains our data
  if (result.response?.type === "echo" && result.response?.data) {
    const echoed = result.response.data as Record<string, unknown>;
    if (echoed.test === "ping") {
      return { success: true, latencyMs: endTime - startTime };
    }
  }

  return { success: false, error: "Echo response did not match sent message" };
}

/**
 * Attempt WebSocket connection and expect it to fail (for negative tests).
 *
 * @param page - Playwright page
 * @param wsUrl - WebSocket URL
 * @param timeout - Timeout in ms
 * @returns True if connection was rejected as expected
 */
export async function expectWebSocketRejected(
  page: Page,
  wsUrl: string,
  timeout: number = timeouts.short
): Promise<boolean> {
  const result = await connectWebSocket(page, wsUrl, timeout);
  return !result.success;
}

/**
 * Get WebSocket URL from HTTP URL.
 * Converts https:// to wss:// and http:// to ws://.
 *
 * @param httpUrl - HTTP(S) URL
 * @param path - Optional path to append
 * @returns WebSocket URL
 */
export function toWebSocketUrl(httpUrl: string, path: string = ""): string {
  const url = new URL(httpUrl);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  if (path) {
    url.pathname = path.startsWith("/") ? path : `/${path}`;
  }
  return url.toString();
}
