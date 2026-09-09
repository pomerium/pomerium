import { FullConfig } from "@playwright/test";
import https from "https";
import http from "http";
import { urls, paths } from "./fixtures/test-data.js";

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

  // Hosted-authenticate suite checks (make up-hosted). The three local
  // instances only exist when the "hosted" compose profile is active, and the
  // cloud check fails fast on missing internet / a hosted-service outage.
  if (process.env.HOSTED_E2E) {
    checks.push(
      { name: "Pomerium hosted-new healthz", url: `${urls.authenticateHostedNew}/healthz` },
      { name: "Pomerium hosted-old healthz", url: `${urls.verifyHostedOld}/healthz` },
      {
        name: "Pomerium hosted-priority healthz",
        url: `${urls.verifyHostedPriority}/healthz`,
      },
      {
        name: "Hosted authenticate (cloud) reachability",
        url: `${urls.hostedAuthenticate}${paths.hpkePublicKey}`,
      },
    );
  }

  console.log("Verifying service availability:");

  const results = await Promise.allSettled(
    checks.map((check) => checkUrl(check.url, check.name))
  );
  let failedCheck: string | undefined;
  results.forEach((result, i) => {
    const check = checks[i];
    if (result.status === "fulfilled") {
      console.log(`  ✓ ${check.name}: OK`);
    } else {
      const message =
        result.reason instanceof Error ? result.reason.message : String(result.reason);
      console.log(`  ✗ ${check.name}: ${message}`);
      failedCheck ??= check.name;
    }
  });
  if (failedCheck) {
    throw new Error(
      `Service check failed for ${failedCheck}. ` +
      `Ensure all services are running with 'make up' or 'docker compose up -d --wait'.`
    );
  }

  console.log("");
  console.log("All services are available. Starting tests...\n");
}

/**
 * Check if a URL is reachable.
 * Uses explicit rejectUnauthorized: false for HTTPS since we use self-signed certs.
 */
function checkUrl(url: string, name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const isHttps = url.startsWith("https://");
    const client = isHttps ? https : http;
    const options = isHttps ? { rejectUnauthorized: false } : {};

    const req = client.get(url, options, (res) => {
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
