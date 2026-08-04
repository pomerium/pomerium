// Keycloak browser-login helpers for the MCP suite. The generic form primitives
// now live in the shared package (suites/shared/keycloak-login); these thin
// adapters keep this suite's (page) / (page, user) call signatures used by
// mcp-client/connect.ts and mcp-client/oauth-raw.ts.

import { type Page } from "@playwright/test";
import {
  submitLoginForm as submitSharedLoginForm,
  waitForKeycloakLoginPage,
} from "../../shared/keycloak-login.js";
import { KEYCLOAK_HOST } from "./constants.js";
import type { TestUser } from "../../shared/users.js";

/** Wait until the browser is on the Keycloak login page. */
export async function waitForLoginPage(page: Page): Promise<void> {
  await waitForKeycloakLoginPage(page, KEYCLOAK_HOST);
}

/** Fill and submit the Keycloak username/password form. */
export async function submitLoginForm(page: Page, user: TestUser): Promise<void> {
  await submitSharedLoginForm(page, user.email, user.password);
}
