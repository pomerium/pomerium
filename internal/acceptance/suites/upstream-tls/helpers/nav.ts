// Navigation helper that survives net::ERR_NETWORK_CHANGED.
//
// Container starts/stops on the shared Docker network (global setup boots the
// stack; the config-validation spec boots throwaway Pomerium containers
// mid-run) can churn a CI runner's network, and a navigation that races such a
// change is aborted by Chromium with ERR_NETWORK_CHANGED. Retrying only the
// navigation lets the network settle without touching any container.

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
