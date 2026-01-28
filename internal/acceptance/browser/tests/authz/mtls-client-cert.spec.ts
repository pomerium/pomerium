/**
 * mTLS Client Certificate Tests
 *
 * Priority: P1
 * Validates: Mutual TLS client certificate authentication through Pomerium
 *
 * GitHub Issues:
 * - #4469: mTLS logging (valid-client-certificate reason)
 * - #4463: mTLS parsing logic
 * - #1587: Per-policy mTLS support
 *
 * Test Architecture:
 * - mtls.localhost.pomerium.io - mTLS domain with CA chain validation
 * - app.localhost.pomerium.io - Non-mTLS domain for comparison
 */

import { test, expect } from "@playwright/test";
import { login } from "../../helpers/authn-flow.js";
import {
  createMTLSContext,
  createNoCertContext,
  makeMTLSRequest,
  certsExist,
  mtlsUrls,
} from "../../helpers/mtls.js";
import { testUsers } from "../../fixtures/users.js";

// Skip all mTLS tests if certificates don't exist
test.beforeAll(() => {
  if (!certsExist("valid")) {
    console.warn(
      "mTLS certificates not found. Run scripts/gen-mtls-certs.sh to generate them."
    );
  }
});

test.describe("mTLS Client Certificate", () => {
  test.skip(!certsExist("valid"), "mTLS certificates not available");

  test("should accept valid client certificate signed by root CA", async ({ browser }) => {
    const context = await createMTLSContext(browser, "valid", mtlsUrls.mtls);

    try {
      const page = await context.newPage();

      // mTLS domain uses public access - the client cert IS the authentication
      // No IdP login needed; just test that the TLS handshake succeeds with valid cert
      const result = await makeMTLSRequest(page, mtlsUrls.mtls);

      expect(result.success, `Request with valid cert should succeed: ${result.error}`).toBe(true);
      expect(result.status).toBe(200);
      expect(result.clientCertAccepted).toBe(true);
    } finally {
      await context.close();
    }
  });

  test("should accept certificate signed by intermediate CA", async ({ browser }) => {
    test.skip(!certsExist("chain"), "Chain certificate not available");

    const context = await createMTLSContext(browser, "chain", mtlsUrls.mtls);

    try {
      const page = await context.newPage();

      // Intermediate CA cert should be accepted via CA chain validation
      const result = await makeMTLSRequest(page, mtlsUrls.mtls);

      expect(result.success, `Intermediate CA cert should be accepted: ${result.error}`).toBe(true);
    } finally {
      await context.close();
    }
  });

  test("should reject certificate from untrusted CA", async ({ browser }) => {
    test.skip(!certsExist("wrong-ca"), "Wrong CA certificate not available");

    const context = await createMTLSContext(browser, "wrong-ca", mtlsUrls.mtls);

    try {
      const page = await context.newPage();

      const result = await makeMTLSRequest(page, mtlsUrls.mtls);

      // Should fail - cert not trusted
      expect(result.success).toBe(false);
    } finally {
      await context.close();
    }
  });

  test("should reject request without client certificate", async ({ browser }) => {
    const context = await createNoCertContext(browser);

    try {
      const page = await context.newPage();

      const result = await makeMTLSRequest(page, mtlsUrls.mtls);

      // Should fail - no cert provided
      expect(result.success).toBe(false);
    } finally {
      await context.close();
    }
  });

  test("should allow access without certificate on non-mTLS domain", async ({ browser }) => {
    const context = await createNoCertContext(browser);

    try {
      const page = await context.newPage();

      // Non-mTLS domain should work without client cert
      await login(page, {
        user: testUsers.alice,
        targetUrl: mtlsUrls.app,
      });

      const result = await makeMTLSRequest(page, mtlsUrls.app);

      expect(result.success, `Non-mTLS domain should work without cert: ${result.error}`).toBe(
        true
      );
    } finally {
      await context.close();
    }
  });
});
