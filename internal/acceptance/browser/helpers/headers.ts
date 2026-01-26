/**
 * Header verification helpers for E2E acceptance tests.
 * Provides functions to verify Pomerium-injected headers in upstream responses.
 */

import { Page, expect } from "@playwright/test";
import { headerNames, urls, testRoutes } from "../fixtures/test-data.js";
import { TestUser } from "../fixtures/users.js";

/**
 * Parsed verify response from pomerium/verify service.
 */
export interface VerifyResponse {
  headers: Record<string, string>;
  path?: string;
  host?: string;
  method?: string;
  protocol?: string;
  jwt?: JWTPayload;
}

/**
 * JWT payload structure.
 */
export interface JWTPayload {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  email?: string;
  email_verified?: boolean;
  groups?: string[];
  name?: string;
  preferred_username?: string;
  [key: string]: unknown;
}

/**
 * Navigate to a route and get the verify service response.
 * The verify service shows the headers it receives from Pomerium.
 */
export async function getVerifyResponse(
  page: Page,
  route: string = "/"
): Promise<VerifyResponse> {
  // Navigate to the route to establish authentication
  const response = await page.goto(`${urls.app}${route}`, {
    waitUntil: "domcontentloaded",
  });

  expect(response).not.toBeNull();
  expect(response!.status()).toBe(200);

  // Use page.request.get with the same route to get JSON response
  // The pomerium/verify app responds with JSON when Accept header is application/json
  const jsonResponse = await page.request.get(`${urls.app}${route}`, {
    ignoreHTTPSErrors: true,
    headers: {
      Accept: "application/json",
    },
  });

  if (jsonResponse.ok()) {
    const contentType = jsonResponse.headers()["content-type"] || "";
    if (contentType.includes("application/json")) {
      try {
        const data = await jsonResponse.json();
        return normalizeVerifyResponse(data);
      } catch {
        // JSON parsing failed, fall through
      }
    }
  }

  // Fallback: Try the /json endpoint (uses default route headers)
  const globalJsonResponse = await page.request.get(`${urls.app}/json`, {
    ignoreHTTPSErrors: true,
  });

  if (globalJsonResponse.ok()) {
    try {
      const data = await globalJsonResponse.json();
      return normalizeVerifyResponse(data);
    } catch {
      // JSON parsing failed, fall through
    }
  }

  // Final fallback: Try to extract headers from page content
  const preElement = page.locator("pre").first();
  const preVisible = await preElement.isVisible().catch(() => false);

  if (preVisible) {
    const jsonText = await preElement.textContent();
    if (jsonText) {
      try {
        const parsed = JSON.parse(jsonText);
        if (parsed.headers || parsed.Headers) {
          return normalizeVerifyResponse(parsed);
        }
      } catch {
        // Not JSON, continue to other parsing methods
      }
    }
  }

  // Try to parse headers from HTML content
  const headers = await extractHeadersFromPage(page);

  return {
    headers,
  };
}

/**
 * Normalize the verify response to a standard format.
 */
function normalizeVerifyResponse(data: Record<string, unknown>): VerifyResponse {
  const headers: Record<string, string> = {};

  // Handle different header formats
  const rawHeaders = data.headers || data.Headers || {};

  if (typeof rawHeaders === "object" && rawHeaders !== null) {
    for (const [key, value] of Object.entries(rawHeaders)) {
      if (Array.isArray(value)) {
        headers[key.toLowerCase()] = value.join(", ");
      } else if (typeof value === "string") {
        headers[key.toLowerCase()] = value;
      }
    }
  }

  return {
    headers,
    path: data.path as string | undefined,
    host: data.host as string | undefined,
    method: data.method as string | undefined,
    protocol: data.protocol as string | undefined,
  };
}

/**
 * Extract headers from the page content using various methods.
 */
async function extractHeadersFromPage(page: Page): Promise<Record<string, string>> {
  const headers: Record<string, string> = {};

  // Try to find headers displayed in the page
  const content = await page.content();

  // Common patterns for header display
  const headerPatterns = [
    /x-pomerium-[^:]+:\s*[^\n<]+/gi,
    /X-Pomerium-[^:]+:\s*[^\n<]+/gi,
  ];

  for (const pattern of headerPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      for (const match of matches) {
        const [key, ...valueParts] = match.split(":");
        const value = valueParts.join(":").trim();
        headers[key.toLowerCase()] = value;
      }
    }
  }

  // Also try to get headers from specific elements
  const headerElements = await page.locator('[class*="header"], [data-header]').all();
  for (const element of headerElements) {
    const text = await element.textContent();
    if (text && text.includes(":")) {
      const [key, ...valueParts] = text.split(":");
      const value = valueParts.join(":").trim();
      if (key.toLowerCase().startsWith("x-pomerium")) {
        headers[key.toLowerCase()] = value;
      }
    }
  }

  return headers;
}

/**
 * Verify that required identity headers are present.
 */
export async function verifyIdentityHeaders(
  page: Page,
  route: string,
  expectedUser: TestUser
): Promise<void> {
  const response = await getVerifyResponse(page, route);

  // Check email header
  const emailHeader = response.headers[headerNames.claimEmail.toLowerCase()];
  expect(
    emailHeader,
    `${headerNames.claimEmail} should be present`
  ).toBeDefined();
  expect(emailHeader).toBe(expectedUser.email);

  // Check groups header (if user has groups)
  if (expectedUser.groups.length > 0) {
    const groupsHeader = response.headers[headerNames.claimGroups.toLowerCase()];
    expect(
      groupsHeader,
      `${headerNames.claimGroups} should be present`
    ).toBeDefined();

    // Groups may be comma-separated or JSON array
    for (const group of expectedUser.groups) {
      expect(
        groupsHeader,
        `Groups header should contain ${group}`
      ).toContain(group);
    }
  }
}

/**
 * Verify that the JWT assertion header is present and valid.
 * Uses the Pomerium /.pomerium/jwt endpoint to get the JWT directly.
 */
export async function verifyJWTAssertionHeader(
  page: Page,
  route: string = testRoutes.jwtTest
): Promise<JWTPayload> {
  // First navigate to the route to establish session
  const navResponse = await page.goto(`${urls.app}${route}`, {
    waitUntil: "domcontentloaded",
  });
  expect(navResponse).not.toBeNull();
  expect(navResponse!.status()).toBe(200);

  // Get JWT from Pomerium's built-in /.pomerium/jwt endpoint
  const jwtResponse = await page.request.get(`${urls.app}/.pomerium/jwt`, {
    ignoreHTTPSErrors: true,
  });

  expect(jwtResponse.ok(), "JWT endpoint should return OK").toBe(true);

  const jwtText = await jwtResponse.text();
  expect(jwtText, "JWT response should not be empty").toBeTruthy();

  // Decode the JWT (we don't verify signature in browser tests)
  const payload = decodeJWT(jwtText.trim());

  // Verify required claims
  expect(payload.iss, "JWT should have issuer").toBeDefined();
  expect(payload.sub, "JWT should have subject").toBeDefined();
  expect(payload.exp, "JWT should have expiration").toBeDefined();
  expect(payload.iat, "JWT should have issued at").toBeDefined();

  return payload;
}

/**
 * Verify JWT claims match expected user.
 */
export async function verifyJWTClaims(
  page: Page,
  route: string,
  expectedUser: TestUser
): Promise<void> {
  const jwt = await verifyJWTAssertionHeader(page, route);

  if (expectedUser.email) {
    expect(jwt.email, "JWT email should match user").toBe(expectedUser.email);
  }

  if (expectedUser.groups.length > 0 && jwt.groups) {
    for (const group of expectedUser.groups) {
      expect(
        jwt.groups,
        `JWT groups should contain ${group}`
      ).toContain(group);
    }
  }
}

/**
 * Decode a JWT token (without verification).
 * Only use for inspection in tests - don't use for security decisions.
 */
export function decodeJWT(token: string): JWTPayload {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }

  const payload = parts[1];
  // Base64URL decode
  const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");

  // Handle padding
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);

  // Use Buffer in Node.js or atob in browser
  let jsonStr: string;
  if (typeof Buffer !== "undefined") {
    jsonStr = Buffer.from(padded, "base64").toString("utf-8");
  } else {
    jsonStr = atob(padded);
  }

  return JSON.parse(jsonStr);
}

/**
 * Verify that a specific header is present with expected value.
 */
export async function verifyHeader(
  page: Page,
  route: string,
  headerName: string,
  expectedValue?: string | RegExp
): Promise<void> {
  const response = await getVerifyResponse(page, route);
  const headerValue = response.headers[headerName.toLowerCase()];

  expect(
    headerValue,
    `Header ${headerName} should be present`
  ).toBeDefined();

  if (expectedValue !== undefined) {
    if (expectedValue instanceof RegExp) {
      expect(
        headerValue,
        `Header ${headerName} should match ${expectedValue}`
      ).toMatch(expectedValue);
    } else {
      expect(
        headerValue,
        `Header ${headerName} should be ${expectedValue}`
      ).toBe(expectedValue);
    }
  }
}

/**
 * Verify that a header is absent.
 */
export async function verifyHeaderAbsent(
  page: Page,
  route: string,
  headerName: string
): Promise<void> {
  const response = await getVerifyResponse(page, route);
  const headerValue = response.headers[headerName.toLowerCase()];

  expect(
    headerValue,
    `Header ${headerName} should be absent`
  ).toBeUndefined();
}

/**
 * Get all Pomerium-injected headers from a response.
 */
export async function getPomeriumHeaders(
  page: Page,
  route: string
): Promise<Record<string, string>> {
  const response = await getVerifyResponse(page, route);

  const pomeriumHeaders: Record<string, string> = {};

  for (const [key, value] of Object.entries(response.headers)) {
    if (key.startsWith("x-pomerium-")) {
      pomeriumHeaders[key] = value;
    }
  }

  return pomeriumHeaders;
}

/**
 * Print all headers for debugging.
 */
export async function debugPrintHeaders(
  page: Page,
  route: string
): Promise<void> {
  const response = await getVerifyResponse(page, route);

  console.log("\n=== Request Headers (as seen by upstream) ===");
  for (const [key, value] of Object.entries(response.headers)) {
    console.log(`  ${key}: ${value}`);
  }
  console.log("==============================================\n");
}
