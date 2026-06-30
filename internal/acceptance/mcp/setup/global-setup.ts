// Playwright global setup: boot the whole container stack once before any test.
//
// Worker processes are spawned after this returns and inherit process.env, so
// setting NODE_EXTRA_CA_CERTS here makes the mkcert root CA trusted by the MCP
// client's HTTPS calls to Pomerium. (The Makefile also exports it, belt-and-
// suspenders, for when `playwright test` is invoked directly.)

import type { FullConfig } from "@playwright/test";
import { startStack } from "./containers.js";
import { MCP_SERVER_URL } from "../mcp-client/constants.js";

export default async function globalSetup(_config: FullConfig): Promise<void> {
  console.log("\n=== Pomerium MCP e2e — booting containers (testcontainers) ===");
  const stack = await startStack();

  process.env.NODE_EXTRA_CA_CERTS = stack.certs.caRoot;
  process.env.POMERIUM_MCP_URL = MCP_SERVER_URL;

  console.log(`  MCP route:           ${MCP_SERVER_URL}`);
  console.log("  Keycloak realm:      http://keycloak.localhost.pomerium.io:8080/realms/pomerium-e2e");
  console.log(`  NODE_EXTRA_CA_CERTS: ${stack.certs.caRoot}`);
  console.log("=== containers ready ===\n");
}
