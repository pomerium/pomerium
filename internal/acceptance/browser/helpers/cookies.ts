/**
 * Cookie inspection helpers for E2E acceptance tests.
 * Provides functions to verify cookie properties.
 */

import { Page, Cookie, expect } from "@playwright/test";
import { cookieNames, urls } from "../fixtures/test-data.js";

/**
 * Expected cookie properties for verification.
 */
export interface ExpectedCookieProps {
  name: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "Strict" | "Lax" | "None";
  domain?: string;
  path?: string;
  hasValue?: boolean;
}

/**
 * Get all cookies from the current browser context.
 */
export async function getAllCookies(page: Page): Promise<Cookie[]> {
  return page.context().cookies();
}

/**
 * Get cookies for a specific domain.
 */
export async function getCookiesForDomain(
  page: Page,
  domain: string
): Promise<Cookie[]> {
  const allCookies = await getAllCookies(page);
  return allCookies.filter((c) => c.domain.includes(domain));
}

/**
 * Get a specific cookie by name.
 */
export async function getCookieByName(
  page: Page,
  name: string | RegExp
): Promise<Cookie | undefined> {
  const allCookies = await getAllCookies(page);
  let pred: (c: Cookie) => boolean;
  if (name instanceof RegExp) {
    name.lastIndex = 0;
    pred = (c) => name.test(c.name);
  } else {
    pred = (c) => c.name === name;
  }
  return allCookies.find(pred);
}

/**
 * Get the Pomerium session cookie.
 */
export async function getSessionCookie(page: Page): Promise<Cookie | undefined> {
  return getCookieByName(page, cookieNames.session);
}

/**
 * Get the Pomerium CSRF cookie.
 */
export async function getCSRFCookie(page: Page): Promise<Cookie | undefined> {
  return getCookieByName(page, cookieNames.csrf);
}

/**
 * Verify that a cookie exists with expected properties.
 */
export async function verifyCookieProperties(
  page: Page,
  expected: ExpectedCookieProps
): Promise<void> {
  const cookie = await getCookieByName(page, expected.name);

  expect(
    cookie,
    `Cookie '${expected.name}' should exist`
  ).toBeDefined();

  if (!cookie) return;

  if (expected.httpOnly !== undefined) {
    expect(
      cookie.httpOnly,
      `Cookie '${expected.name}' httpOnly should be ${expected.httpOnly}`
    ).toBe(expected.httpOnly);
  }

  if (expected.secure !== undefined) {
    expect(
      cookie.secure,
      `Cookie '${expected.name}' secure should be ${expected.secure}`
    ).toBe(expected.secure);
  }

  if (expected.sameSite !== undefined) {
    expect(
      cookie.sameSite,
      `Cookie '${expected.name}' sameSite should be ${expected.sameSite}`
    ).toBe(expected.sameSite);
  }

  if (expected.domain !== undefined) {
    expect(
      cookie.domain,
      `Cookie '${expected.name}' domain should contain ${expected.domain}`
    ).toContain(expected.domain);
  }

  if (expected.path !== undefined) {
    expect(
      cookie.path,
      `Cookie '${expected.name}' path should be ${expected.path}`
    ).toBe(expected.path);
  }

  if (expected.hasValue) {
    expect(
      cookie.value.length,
      `Cookie '${expected.name}' should have a value`
    ).toBeGreaterThan(0);
  }
}

/**
 * Verify that the session cookie has correct security properties.
 * Per RFC: HttpOnly, Secure, SameSite=Lax
 */
export async function verifySessionCookieSecurity(page: Page): Promise<void> {
  await verifyCookieProperties(page, {
    name: cookieNames.session,
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    hasValue: true,
  });
}

/**
 * Verify that the CSRF cookie has correct security properties.
 * Per RFC: HttpOnly, Secure
 */
export async function verifyCSRFCookieSecurity(page: Page): Promise<void> {
  await verifyCookieProperties(page, {
    name: cookieNames.csrf,
    httpOnly: true,
    secure: true,
    path: "/",
    hasValue: true,
  });
}

/**
 * Verify that a cookie is absent (e.g., after logout).
 */
export async function verifyCookieAbsent(
  page: Page,
  cookieName: string
): Promise<void> {
  const cookie = await getCookieByName(page, cookieName);
  expect(
    cookie,
    `Cookie '${cookieName}' should not exist`
  ).toBeUndefined();
}

/**
 * Verify that the session cookie is absent.
 */
export async function verifySessionCookieAbsent(page: Page): Promise<void> {
  await verifyCookieAbsent(page, cookieNames.session);
}

/**
 * Get cookie expiration as a Date object.
 */
export function getCookieExpiration(cookie: Cookie): Date | null {
  if (cookie.expires === -1) {
    return null; // Session cookie
  }
  return new Date(cookie.expires * 1000);
}

/**
 * Check if a cookie is expired.
 */
export function isCookieExpired(cookie: Cookie): boolean {
  const expiration = getCookieExpiration(cookie);
  if (expiration === null) {
    return false; // Session cookies don't expire
  }
  return expiration < new Date();
}

/**
 * Print all cookies for debugging.
 */
export async function debugPrintCookies(page: Page): Promise<void> {
  const cookies = await getAllCookies(page);
  console.log("\n=== Cookies ===");
  for (const cookie of cookies) {
    console.log(`  ${cookie.name}:`);
    console.log(`    value: ${cookie.value.substring(0, 50)}...`);
    console.log(`    domain: ${cookie.domain}`);
    console.log(`    path: ${cookie.path}`);
    console.log(`    httpOnly: ${cookie.httpOnly}`);
    console.log(`    secure: ${cookie.secure}`);
    console.log(`    sameSite: ${cookie.sameSite}`);
    console.log(`    expires: ${getCookieExpiration(cookie)}`);
  }
  console.log("===============\n");
}
