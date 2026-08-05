// Navigation helper that survives net::ERR_NETWORK_CHANGED.
//
// The suite restarts the Pomerium container between spec groups; on CI that
// churns the runner's Docker network, and a navigation that races a restart is
// aborted by Chromium with ERR_NETWORK_CHANGED. Retrying only the navigation
// lets the network settle without touching the container.

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
