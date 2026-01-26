import { FullConfig } from "@playwright/test";
import https from "https";
import http from "http";

/**
 * Global setup for Pomerium E2E acceptance tests.
 * Verifies that all required services are available before running tests.
 */
async function globalSetup(_config: FullConfig): Promise<void> {
  console.log("\n=== Pomerium E2E Acceptance Tests ===\n");

  const pomeriumUrl = process.env.POMERIUM_URL || "https://app.localhost.pomerium.io:8443";
  const authenticateUrl = process.env.AUTHENTICATE_URL || "https://authenticate.localhost.pomerium.io:8443";
  const keycloakUrl = process.env.KEYCLOAK_URL || "http://keycloak.localhost.pomerium.io:8080";

  console.log("Configuration:");
  console.log(`  Pomerium URL: ${pomeriumUrl}`);
  console.log(`  Authenticate URL: ${authenticateUrl}`);
  console.log(`  Keycloak URL: ${keycloakUrl}`);
  console.log(`  Run ID: ${process.env.RUN_ID || "default"}`);
  console.log("");

  // Verify services are reachable
  const checks = [
    {
      name: "Keycloak realm",
      url: `${keycloakUrl}/realms/pomerium-e2e`,
    },
    {
      name: "Keycloak OIDC discovery",
      url: `${keycloakUrl}/realms/pomerium-e2e/.well-known/openid-configuration`,
    },
    {
      name: "Pomerium healthz",
      url: `${authenticateUrl}/healthz`,
    },
    {
      name: "Pomerium ping",
      url: `${authenticateUrl}/ping`,
    },
  ];

  console.log("Verifying service availability:");

  for (const check of checks) {
    try {
      await checkUrl(check.url, check.name);
      console.log(`  ✓ ${check.name}: OK`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.log(`  ✗ ${check.name}: ${message}`);
      throw new Error(
        `Service check failed for ${check.name}. ` +
          `Ensure all services are running with 'make up' or 'docker compose up -d --wait'.`
      );
    }
  }

  console.log("");
  console.log("All services are available. Starting tests...\n");
}

/**
 * Check if a URL is reachable.
 * Certificate validation is handled via NODE_TLS_REJECT_UNAUTHORIZED env var.
 */
function checkUrl(url: string, name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const isHttps = url.startsWith("https://");
    const client = isHttps ? https : http;

    const req = client.get(url, (res) => {
      if (res.statusCode && res.statusCode >= 200 && res.statusCode < 400) {
        // Consume response data to free up memory
        res.resume();
        resolve();
      } else {
        reject(new Error(`HTTP ${res.statusCode}`));
      }
    });

    req.on("error", (err) => {
      reject(new Error(err.message));
    });

    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error("Timeout"));
    });
  });
}

export default globalSetup;
