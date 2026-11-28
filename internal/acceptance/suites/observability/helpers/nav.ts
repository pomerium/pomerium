// Per-test Pomerium restarts churn the Docker network on CI, and a navigation
// that races one is aborted with ERR_NETWORK_CHANGED. A test-level retry does not
// help - it restarts Pomerium and re-triggers the churn - so retry just the
// navigation and let the network settle.

import type { Page, Response } from "@playwright/test";

type GotoOptions = Parameters<Page["goto"]>[1];

/** page.goto that retries transient ERR_NETWORK_CHANGED aborts. */
export async function gotoStable(
  page: Page,
  url: string,
  options?: GotoOptions,
  attempts = 4,
): Promise<Response | null> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await page.goto(url, options);
    } catch (err) {
      if (attempt < attempts && /ERR_NETWORK_CHANGED/.test(String(err))) {
        await page.waitForTimeout(500);
        continue;
      }
      throw err;
    }
  }
}
