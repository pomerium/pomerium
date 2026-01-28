/**
 * mTLS helpers for E2E acceptance tests.
 * Provides functions to test mutual TLS client certificate authentication through Pomerium.
 */

import { Browser, BrowserContext, Page } from "@playwright/test";
import { urls, timeouts } from "../fixtures/test-data.js";
import * as fs from "fs";
import * as path from "path";

/**
 * Client certificate types available for testing.
 */
export type ClientCertType =
  | "valid" // Valid cert signed by trusted CA
  | "chain" // Valid cert signed by intermediate CA
  | "wrong-ca"; // Cert signed by untrusted CA

/**
 * mTLS certificate paths.
 */
export interface CertPaths {
  cert: string;
  key: string;
  passphrase?: string;
}

/**
 * Result of an mTLS request.
 */
export interface MTLSRequestResult {
  success: boolean;
  status?: number;
  error?: string;
  clientCertAccepted: boolean;
  responseData?: unknown;
}

/**
 * Base path for mTLS certificates.
 * Relative to the acceptance test directory.
 */
const MTLS_CERTS_BASE = path.resolve(__dirname, "../../certs/mtls");

/**
 * Get certificate paths for a given certificate type.
 *
 * @param certType - Type of certificate to get
 * @returns Certificate and key paths
 */
export function getCertPaths(certType: ClientCertType): CertPaths {
  const certMap: Record<ClientCertType, CertPaths> = {
    valid: {
      cert: path.join(MTLS_CERTS_BASE, "client-valid.crt"),
      key: path.join(MTLS_CERTS_BASE, "client-valid.key"),
    },
    chain: {
      cert: path.join(MTLS_CERTS_BASE, "client-chain-full.crt"),
      key: path.join(MTLS_CERTS_BASE, "client-chain.key"),
    },
    "wrong-ca": {
      cert: path.join(MTLS_CERTS_BASE, "client-wrong-ca.crt"),
      key: path.join(MTLS_CERTS_BASE, "client-wrong-ca.key"),
    },
  };

  return certMap[certType];
}

/**
 * Check if mTLS certificates exist.
 *
 * @param certType - Type of certificate to check
 * @returns True if certificates exist
 */
export function certsExist(certType: ClientCertType): boolean {
  const paths = getCertPaths(certType);
  try {
    fs.accessSync(paths.cert, fs.constants.R_OK);
    fs.accessSync(paths.key, fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * mTLS domain URLs.
 */
export const mtlsUrls = {
  /** mTLS domain - accepts certs from root and intermediate CA */
  mtls: process.env.MTLS_URL || "https://mtls.localhost.pomerium.io:8443",
  /** App URL (non-mTLS) for comparison testing */
  app: urls.app,
};

/**
 * Create a browser context with client certificate configured.
 *
 * Playwright supports client certificates via the `clientCertificates` option
 * in `browser.newContext()`.
 *
 * @param browser - Playwright browser instance
 * @param certType - Type of client certificate to use
 * @param origin - Origin to apply the certificate to
 * @returns Browser context with client certificate
 */
export async function createMTLSContext(
  browser: Browser,
  certType: ClientCertType,
  origin: string = mtlsUrls.mtls
): Promise<BrowserContext> {
  const certPaths = getCertPaths(certType);

  // Verify certs exist
  if (!certsExist(certType)) {
    throw new Error(
      `mTLS certificates for type '${certType}' not found at ${certPaths.cert}. ` +
        `Run 'scripts/gen-mtls-certs.sh' to generate them.`
    );
  }

  // Parse origin to get just the origin part
  const url = new URL(origin);
  const originStr = url.origin;

  return browser.newContext({
    ignoreHTTPSErrors: true,
    clientCertificates: [
      {
        origin: originStr,
        certPath: certPaths.cert,
        keyPath: certPaths.key,
      },
    ],
  });
}

/**
 * Create a browser context without any client certificate.
 *
 * @param browser - Playwright browser instance
 * @returns Browser context without client certificate
 */
export async function createNoCertContext(browser: Browser): Promise<BrowserContext> {
  return browser.newContext({
    ignoreHTTPSErrors: true,
    // No clientCertificates
  });
}

/**
 * Make a request to an mTLS-protected endpoint.
 *
 * @param page - Playwright page (from an mTLS context)
 * @param url - URL to request
 * @returns Request result
 */
export async function makeMTLSRequest(page: Page, url: string): Promise<MTLSRequestResult> {
  try {
    const response = await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout: timeouts.medium,
    });

    if (!response) {
      return {
        success: false,
        error: "No response received",
        clientCertAccepted: false,
      };
    }

    const status = response.status();
    const success = status === 200;

    let responseData: unknown;
    if (success) {
      try {
        // Try to get JSON response from verify service
        const jsonResponse = await page.request.get(url, {
          ignoreHTTPSErrors: true,
          headers: { Accept: "application/json" },
        });
        if (jsonResponse.ok()) {
          responseData = await jsonResponse.json().catch(() => null);
        }
      } catch {
        // Ignore JSON parsing errors
      }
    }

    return {
      success,
      status,
      clientCertAccepted: success,
      responseData,
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);

    // Check for TLS handshake failure (cert rejected at connection level)
    const isTLSError =
      errorMsg.includes("SSL") ||
      errorMsg.includes("TLS") ||
      errorMsg.includes("certificate") ||
      errorMsg.includes("handshake");

    return {
      success: false,
      error: errorMsg,
      clientCertAccepted: !isTLSError,
    };
  }
}

/**
 * Test that an mTLS request succeeds with the given certificate type.
 *
 * @param browser - Playwright browser
 * @param url - URL to request
 * @param certType - Type of client certificate to use
 * @returns True if request succeeded
 */
export async function expectMTLSSuccess(
  browser: Browser,
  url: string,
  certType: ClientCertType
): Promise<boolean> {
  const context = await createMTLSContext(browser, certType);
  try {
    const page = await context.newPage();
    const result = await makeMTLSRequest(page, url);
    return result.success && result.clientCertAccepted;
  } finally {
    await context.close();
  }
}

/**
 * Test that an mTLS request fails with the given certificate type.
 *
 * @param browser - Playwright browser
 * @param url - URL to request
 * @param certType - Type of client certificate to use
 * @returns True if request was rejected
 */
export async function expectMTLSRejected(
  browser: Browser,
  url: string,
  certType: ClientCertType
): Promise<boolean> {
  const context = await createMTLSContext(browser, certType);
  try {
    const page = await context.newPage();
    const result = await makeMTLSRequest(page, url);
    return !result.success || !result.clientCertAccepted;
  } finally {
    await context.close();
  }
}

/**
 * Test that a request without any client certificate fails.
 *
 * @param browser - Playwright browser
 * @param url - URL to request
 * @returns True if request was rejected
 */
export async function expectNoCertRejected(browser: Browser, url: string): Promise<boolean> {
  const context = await createNoCertContext(browser);
  try {
    const page = await context.newPage();
    const result = await makeMTLSRequest(page, url);
    return !result.success;
  } finally {
    await context.close();
  }
}

/**
 * Get the valid client certificate fingerprint.
 * Used for policy matching.
 */
export function getValidCertFingerprint(): string | null {
  const fingerprintPath = path.join(MTLS_CERTS_BASE, "client-valid.fingerprint");
  try {
    return fs.readFileSync(fingerprintPath, "utf-8").trim();
  } catch {
    return null;
  }
}

/**
 * mTLS test routes - using domain-based TLS configuration.
 * Each mTLS domain serves at "/" since TLS config is per-listener.
 */
export const mtlsRoutes = {
  /** Default route path for all mTLS domains */
  default: "/",
};
