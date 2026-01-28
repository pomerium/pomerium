/**
 * Custom wait helpers for E2E acceptance tests.
 * Provides functions for polling and waiting on conditions.
 */

import { Page, expect } from "@playwright/test";
import { timeouts } from "../fixtures/test-data.js";

/**
 * Options for polling operations.
 */
export interface PollOptions {
  /** Maximum time to wait in milliseconds */
  timeout?: number;
  /** Interval between polls in milliseconds */
  interval?: number;
  /** Description for error messages */
  description?: string;
}

/**
 * Poll until a condition is true.
 */
export async function pollUntil(
  condition: () => Promise<boolean>,
  options: PollOptions = {}
): Promise<void> {
  const {
    timeout = timeouts.medium,
    interval = timeouts.pollInterval,
    description = "condition",
  } = options;

  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    if (await condition()) {
      return;
    }
    await sleep(interval);
  }

  throw new Error(`Timeout waiting for ${description} after ${timeout}ms`);
}

/**
 * Sleep for a specified duration.
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Wait for a URL to match a pattern.
 */
export async function waitForUrlMatch(
  page: Page,
  pattern: RegExp | string,
  options: PollOptions = {}
): Promise<void> {
  const { timeout = timeouts.long } = options;

  if (typeof pattern === "string") {
    await page.waitForURL(pattern, { timeout });
  } else {
    await page.waitForURL(pattern, { timeout });
  }
}

/**
 * Wait for a URL to NOT match a pattern.
 */
export async function waitForUrlNotMatch(
  page: Page,
  pattern: RegExp | string,
  options: PollOptions = {}
): Promise<void> {
  await pollUntil(
    async () => {
      const url = page.url();
      if (typeof pattern === "string") {
        return !url.includes(pattern);
      }
      return !pattern.test(url);
    },
    {
      ...options,
      description: `URL to not match ${pattern}`,
    }
  );
}

/**
 * Wait for a cookie to be set.
 */
export async function waitForCookie(
  page: Page,
  cookieName: string,
  options: PollOptions = {}
): Promise<void> {
  await pollUntil(
    async () => {
      const cookies = await page.context().cookies();
      return cookies.some((c) => c.name === cookieName);
    },
    {
      ...options,
      description: `cookie '${cookieName}' to be set`,
    }
  );
}

/**
 * Wait for a cookie to be removed.
 */
export async function waitForCookieRemoved(
  page: Page,
  cookieName: string,
  options: PollOptions = {}
): Promise<void> {
  await pollUntil(
    async () => {
      const cookies = await page.context().cookies();
      return !cookies.some((c) => c.name === cookieName);
    },
    {
      ...options,
      description: `cookie '${cookieName}' to be removed`,
    }
  );
}

/**
 * Wait for HTTP status code from a URL.
 */
export async function waitForHttpStatus(
  page: Page,
  url: string,
  expectedStatus: number,
  options: PollOptions = {}
): Promise<void> {
  await pollUntil(
    async () => {
      try {
        const response = await page.request.get(url, {
          ignoreHTTPSErrors: true,
        });
        return response.status() === expectedStatus;
      } catch {
        return false;
      }
    },
    {
      ...options,
      description: `HTTP ${expectedStatus} from ${url}`,
    }
  );
}

/**
 * Wait for token to expire (based on Keycloak short lifespan).
 * Waits for accessTokenLifespan + buffer.
 */
export async function waitForTokenExpiry(): Promise<void> {
  const buffer =
    process.env.CI ? timeouts.tokenExpiryBuffer * 2 : timeouts.tokenExpiryBuffer;
  const waitTime = timeouts.accessTokenLifespan + buffer;
  const startTime = Date.now();

  console.log(`Waiting ${waitTime}ms for token expiry...`);
  await pollUntil(
    async () => Date.now() - startTime >= waitTime,
    {
      timeout: waitTime + timeouts.pollInterval,
      interval: timeouts.pollInterval,
      description: "token expiry",
    }
  );
}

/**
 * Wait for session to become idle (based on Keycloak ssoSessionIdle).
 */
export async function waitForSessionIdle(): Promise<void> {
  const waitTime = timeouts.ssoSessionIdle + timeouts.tokenExpiryBuffer;
  console.log(`Waiting ${waitTime}ms for session idle timeout...`);
  await sleep(waitTime);
}

/**
 * Wait for network idle (no pending requests).
 */
export async function waitForNetworkIdle(
  page: Page,
  options: { timeout?: number } = {}
): Promise<void> {
  await page.waitForLoadState("networkidle", {
    timeout: options.timeout ?? timeouts.medium,
  });
}

/**
 * Wait for a specific element to appear.
 */
export async function waitForElement(
  page: Page,
  selector: string,
  options: PollOptions = {}
): Promise<void> {
  const { timeout = timeouts.medium } = options;
  await page.waitForSelector(selector, { timeout, state: "visible" });
}

/**
 * Wait for a specific element to disappear.
 */
export async function waitForElementHidden(
  page: Page,
  selector: string,
  options: PollOptions = {}
): Promise<void> {
  const { timeout = timeouts.medium } = options;
  await page.waitForSelector(selector, { timeout, state: "hidden" });
}

/**
 * Wait for page to be fully loaded and stable.
 */
export async function waitForPageStable(page: Page): Promise<void> {
  await page.waitForLoadState("domcontentloaded");
  await page.waitForLoadState("networkidle");
  // Small buffer for any final JS execution
  await sleep(100);
}

/**
 * Retry an action until it succeeds or times out.
 */
export async function retry<T>(
  action: () => Promise<T>,
  options: PollOptions & { retries?: number } = {}
): Promise<T> {
  const {
    timeout = timeouts.medium,
    interval = timeouts.pollInterval,
    retries = Math.ceil(timeout / interval),
    description = "action",
  } = options;

  let lastError: Error | undefined;

  for (let i = 0; i < retries; i++) {
    try {
      return await action();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      if (i < retries - 1) {
        await sleep(interval);
      }
    }
  }

  throw new Error(
    `Failed to ${description} after ${retries} retries: ${lastError?.message}`
  );
}
