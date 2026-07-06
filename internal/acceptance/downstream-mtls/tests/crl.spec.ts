/**
 * Group C - Certificate Revocation Lists.
 * Test plan: Client Certificates (mTLS), TC-CC-09..11.
 *
 * Fixtures (scripts/gen-certs.sh): client-revoked is a root-signed leaf whose
 * serial is listed in crl-root.pem; crl-intermediate.pem is the intermediate
 * CA's empty CRL; crl-chain.pem bundles both.
 */

import { test } from "@playwright/test";
import { expectDenied495, expectUpstreamReached, withCert } from "../helpers/api.js";
import { rootCRLBase64 } from "../helpers/fixtures.js";
import { startPomerium, type PomeriumOptions, type StartedPomerium } from "../setup/containers.js";
import { CONTAINER_CERTS, generateConfig } from "../setup/pomerium-config.js";

test.describe("Group C: certificate revocation lists", () => {
  // TC-CC-09 (crl_file) + TC-CC-11 (crl inline / env vars): the same CRL is
  // supplied through each surface and revocation must behave identically.
  const surfaces: Array<{ id: string; title: string; opts: PomeriumOptions }> = [
    {
      id: "TC-CC-09",
      title: "downstream_mtls.crl_file",
      opts: {
        configFile: generateConfig({
          name: "crl-file",
          downstreamMtls: { ca_file: CONTAINER_CERTS.rootCA, crl_file: CONTAINER_CERTS.crlRoot },
          route: { publicAccess: true },
        }),
      },
    },
    {
      id: "TC-CC-11a",
      title: "downstream_mtls.crl (inline base64)",
      opts: {
        configFile: generateConfig({
          name: "crl-inline",
          downstreamMtls: { ca_file: CONTAINER_CERTS.rootCA, crl: rootCRLBase64() },
          route: { publicAccess: true },
        }),
      },
    },
    {
      id: "TC-CC-11b",
      title: "DOWNSTREAM_MTLS_CRL_FILE environment variable",
      opts: {
        configFile: generateConfig({
          name: "crl-env-file",
          downstreamMtls: { ca_file: CONTAINER_CERTS.rootCA },
          route: { publicAccess: true },
        }),
        env: { DOWNSTREAM_MTLS_CRL_FILE: CONTAINER_CERTS.crlRoot },
      },
    },
    {
      id: "TC-CC-11c",
      title: "DOWNSTREAM_MTLS_CRL environment variable (inline base64)",
      opts: {
        configFile: generateConfig({
          name: "crl-env-inline",
          downstreamMtls: { ca_file: CONTAINER_CERTS.rootCA },
          route: { publicAccess: true },
        }),
        env: { DOWNSTREAM_MTLS_CRL: rootCRLBase64() },
      },
    },
  ];

  for (const surface of surfaces) {
    test(`${surface.id}: ${surface.title} - revoked leaf denied, non-revoked allowed`, async () => {
      const pomerium = await startPomerium(surface.opts);
      try {
        await withCert("revoked", (ctx) => expectDenied495(ctx));
        await withCert("valid", (ctx) => expectUpstreamReached(ctx));
      } finally {
        await pomerium.stop();
      }
    });
  }

  test("TC-CC-10: CRL checks consult the leaf's direct issuer only (partial coverage allowed)", async () => {
    // DEVIATION FROM THE MANUAL TEST PLAN, confirmed against the source: the
    // plan expected "a CRL for any CA in the chain requires a CRL for ALL CAs
    // in the chain", but Pomerium deliberately configures leaf-only CRL
    // checking - OnlyVerifyLeafCertCrl in config/envoyconfig/tls.go and the
    // matching Go-side logic in authorize/evaluator/functions.go ("Consult
    // CRLs only for the first CA in the chain"). So:
    //   - a CRL bundle missing the leaf's ISSUER simply skips revocation
    //     checking for that leaf (partial coverage is not an error), and
    //   - revocation of a chain leaf is enforced via its issuer's CRL.
    let pomerium: StartedPomerium = await startPomerium({
      configFile: generateConfig({
        name: "crl-partial-chain",
        downstreamMtls: { ca_file: CONTAINER_CERTS.caChain, crl_file: CONTAINER_CERTS.crlRoot },
        route: { publicAccess: true },
      }),
    });
    try {
      // Root CRL only: the intermediate-signed leaf has no CRL for its
      // issuer, so no revocation check applies - it is allowed. Even the
      // leaf revoked in the INTERMEDIATE's CRL passes here, because that CRL
      // is not loaded.
      await withCert("chain", (ctx) => expectUpstreamReached(ctx));
      await withCert("chain-revoked", (ctx) => expectUpstreamReached(ctx));
      // Leaves issued by the root ARE checked against the root's CRL.
      await withCert("valid", (ctx) => expectUpstreamReached(ctx));
      await withCert("revoked", (ctx) => expectDenied495(ctx));
    } finally {
      await pomerium.stop();
    }

    // Full-chain CRL bundle: the intermediate's CRL is now loaded, so the
    // chain leaf revoked by the intermediate is denied while its non-revoked
    // sibling still passes.
    pomerium = await startPomerium({
      configFile: generateConfig({
        name: "crl-full-chain",
        downstreamMtls: { ca_file: CONTAINER_CERTS.caChain, crl_file: CONTAINER_CERTS.crlChain },
        route: { publicAccess: true },
      }),
    });
    try {
      await withCert("chain", (ctx) => expectUpstreamReached(ctx));
      await withCert("chain-revoked", (ctx) => expectDenied495(ctx));
    } finally {
      await pomerium.stop();
    }
  });
});
