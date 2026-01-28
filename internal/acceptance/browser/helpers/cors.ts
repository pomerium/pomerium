/**
 * CORS helpers for E2E acceptance tests.
 * Provides functions to test CORS preflight and cross-origin requests through Pomerium.
 */

import { Page, APIResponse } from "@playwright/test";
import { urls, timeouts } from "../fixtures/test-data.js";

/**
 * CORS headers that may be present in a response.
 */
export interface CORSHeaders {
  "access-control-allow-origin"?: string;
  "access-control-allow-methods"?: string;
  "access-control-allow-headers"?: string;
  "access-control-allow-credentials"?: string;
  "access-control-max-age"?: string;
  "access-control-expose-headers"?: string;
}

/**
 * Result of a CORS preflight request.
 */
export interface PreflightResult {
  status: number;
  ok: boolean;
  headers: CORSHeaders;
  allowedOrigin?: string;
  allowedMethods?: string[];
  allowedHeaders?: string[];
  allowsCredentials: boolean;
  /** The final URL after any redirects */
  finalUrl: string;
  /** Whether a redirect occurred (final URL differs from requested URL) */
  wasRedirected: boolean;
}

/**
 * Result of a cross-origin XHR/fetch request.
 */
export interface CrossOriginRequestResult {
  success: boolean;
  status?: number;
  error?: string;
  responseData?: unknown;
  corsHeaders: CORSHeaders;
}

/**
 * Send a CORS preflight (OPTIONS) request to a URL.
 *
 * @param page - Playwright page
 * @param url - Target URL for the preflight
 * @param origin - Origin to send in the request
 * @param requestMethod - Method that will be used in the actual request
 * @param requestHeaders - Headers that will be sent in the actual request
 * @returns Preflight result
 */
export async function sendPreflight(
  page: Page,
  url: string,
  origin: string,
  requestMethod: string = "GET",
  requestHeaders: string[] = []
): Promise<PreflightResult> {
  const headers: Record<string, string> = {
    Origin: origin,
    "Access-Control-Request-Method": requestMethod,
  };

  if (requestHeaders.length > 0) {
    headers["Access-Control-Request-Headers"] = requestHeaders.join(", ");
  }

  const response = await page.request.fetch(url, {
    method: "OPTIONS",
    headers,
    ignoreHTTPSErrors: true,
  });

  const responseHeaders = response.headers();
  const corsHeaders = extractCORSHeaders(responseHeaders);
  const finalUrl = response.url();

  return {
    status: response.status(),
    ok: response.ok(),
    headers: corsHeaders,
    allowedOrigin: corsHeaders["access-control-allow-origin"],
    allowedMethods: corsHeaders["access-control-allow-methods"]?.split(",").map((m) => m.trim()),
    allowedHeaders: corsHeaders["access-control-allow-headers"]?.split(",").map((h) => h.trim()),
    allowsCredentials: corsHeaders["access-control-allow-credentials"] === "true",
    finalUrl,
    wasRedirected: finalUrl !== url,
  };
}

/**
 * Extract CORS-related headers from a response.
 *
 * @param headers - Response headers object
 * @returns CORS headers
 */
export function extractCORSHeaders(headers: Record<string, string>): CORSHeaders {
  const corsHeaders: CORSHeaders = {};
  const corsHeaderNames = [
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-credentials",
    "access-control-max-age",
    "access-control-expose-headers",
  ];

  for (const name of corsHeaderNames) {
    const value = headers[name] || headers[name.toLowerCase()];
    if (value !== undefined) {
      corsHeaders[name as keyof CORSHeaders] = value;
    }
  }

  return corsHeaders;
}

/**
 * Make a cross-origin request from the page context using fetch.
 * This runs in the browser context, so it's subject to actual CORS restrictions.
 *
 * @param page - Playwright page
 * @param url - Target URL
 * @param options - Fetch options
 * @returns Request result
 */
export async function makeCrossOriginRequest(
  page: Page,
  url: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    credentials?: "include" | "omit" | "same-origin";
  } = {}
): Promise<CrossOriginRequestResult> {
  return page.evaluate(
    async ({ targetUrl, fetchOptions }) => {
      try {
        const response = await fetch(targetUrl, {
          method: fetchOptions.method || "GET",
          headers: fetchOptions.headers,
          body: fetchOptions.body,
          credentials: fetchOptions.credentials || "include",
          mode: "cors",
        });

        // Extract CORS headers
        const corsHeaders: Record<string, string | undefined> = {};
        const corsHeaderNames = [
          "access-control-allow-origin",
          "access-control-allow-methods",
          "access-control-allow-headers",
          "access-control-allow-credentials",
          "access-control-max-age",
          "access-control-expose-headers",
        ];

        for (const name of corsHeaderNames) {
          const value = response.headers.get(name);
          if (value) {
            corsHeaders[name] = value;
          }
        }

        let responseData: unknown;
        const contentType = response.headers.get("content-type") || "";
        if (contentType.includes("application/json")) {
          try {
            responseData = await response.json();
          } catch {
            responseData = await response.text();
          }
        } else {
          responseData = await response.text();
        }

        return {
          success: response.ok,
          status: response.status,
          responseData,
          corsHeaders,
        };
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
          corsHeaders: {},
        };
      }
    },
    { targetUrl: url, fetchOptions: options }
  );
}

/**
 * Test that a preflight request succeeds for a given origin.
 *
 * @param page - Playwright page
 * @param url - Target URL
 * @param origin - Origin to test
 * @returns True if preflight succeeds
 */
export async function expectPreflightSuccess(
  page: Page,
  url: string,
  origin: string
): Promise<boolean> {
  const result = await sendPreflight(page, url, origin);
  return (
    result.ok &&
    result.allowedOrigin !== undefined &&
    (result.allowedOrigin === origin || result.allowedOrigin === "*")
  );
}

/**
 * Test that a preflight request is blocked (no CORS headers or rejected origin).
 *
 * @param page - Playwright page
 * @param url - Target URL
 * @param origin - Origin to test
 * @returns True if preflight is blocked
 */
export async function expectPreflightBlocked(
  page: Page,
  url: string,
  origin: string
): Promise<boolean> {
  const result = await sendPreflight(page, url, origin);
  // Blocked if: non-2xx status, or no allow-origin, or allow-origin doesn't match
  return (
    !result.ok ||
    result.allowedOrigin === undefined ||
    (result.allowedOrigin !== origin && result.allowedOrigin !== "*")
  );
}

/**
 * Verify that an actual cross-origin request (not just preflight) works.
 *
 * @param page - Playwright page
 * @param targetUrl - Target URL to request
 * @param origin - Origin making the request (for verification)
 * @param withCredentials - Whether to include credentials
 * @returns True if the cross-origin request succeeded
 */
export async function verifyCrossOriginRequestWorks(
  page: Page,
  targetUrl: string,
  origin: string,
  withCredentials: boolean = true
): Promise<boolean> {
  const result = await makeCrossOriginRequest(page, targetUrl, {
    credentials: withCredentials ? "include" : "omit",
  });

  return result.success;
}

/**
 * Test origins that should be allowed/blocked.
 */
export const testOrigins = {
  /** Origin that should be allowed (same base domain) */
  trusted: "https://trusted.localhost.pomerium.io:8443",
  /** External origin that may be blocked */
  untrusted: "https://untrusted.example.com",
  /** Localhost origin */
  localhost: "http://localhost:3000",
  /** Null origin (some privacy contexts) */
  nullOrigin: "null",
};
