/**
 * Group B - CA configuration surfaces.
 * Test plan: Client Certificates (mTLS), TC-CC-05..08.
 *
 * The same trust root is supplied through each supported surface -
 * downstream_mtls.ca_file, downstream_mtls.ca (inline base64) and the
 * DOWNSTREAM_MTLS_CA_FILE / DOWNSTREAM_MTLS_CA environment variables - and
 * every surface must behave identically: valid leaf allowed, untrusted
 * leaf denied with 495.
 *
 * Routes use public access so assertions isolate the mTLS layer (no login).
 */

import { test } from "@playwright/test";
import { expectDenied495, expectUpstreamReached, withCert } from "../helpers/api.js";
import { rootCABase64 } from "../helpers/fixtures.js";
import { startPomerium, type PomeriumOptions } from "../setup/containers.js";
import { CONTAINER_CERTS, generateConfig } from "../setup/pomerium-config.js";

const variants: Array<{ id: string; title: string; opts: PomeriumOptions }> = [
  {
    id: "TC-CC-05",
    title: "downstream_mtls.ca_file (path)",
    opts: {
      configFile: generateConfig({
        name: "ca-file",
        downstreamMtls: { ca_file: CONTAINER_CERTS.rootCA },
        route: { publicAccess: true },
      }),
    },
  },
  {
    id: "TC-CC-06",
    title: "downstream_mtls.ca (inline base64)",
    opts: {
      configFile: generateConfig({
        name: "ca-inline",
        downstreamMtls: { ca: rootCABase64() },
        route: { publicAccess: true },
      }),
    },
  },
  {
    id: "TC-CC-07",
    title: "DOWNSTREAM_MTLS_CA_FILE environment variable",
    opts: {
      configFile: generateConfig({
        name: "ca-env-file",
        downstreamMtls: null,
        route: { publicAccess: true },
      }),
      env: { DOWNSTREAM_MTLS_CA_FILE: CONTAINER_CERTS.rootCA },
    },
  },
  {
    id: "TC-CC-08",
    title: "DOWNSTREAM_MTLS_CA environment variable (inline base64)",
    opts: {
      configFile: generateConfig({
        name: "ca-env-inline",
        downstreamMtls: null,
        route: { publicAccess: true },
      }),
      env: { DOWNSTREAM_MTLS_CA: rootCABase64() },
    },
  },
];

test.describe("Group B: CA configuration surfaces", () => {
  for (const variant of variants) {
    test(`${variant.id}: ${variant.title} - valid leaf allowed, untrusted denied`, async () => {
      const pomerium = await startPomerium(variant.opts);
      try {
        await withCert("valid", (ctx) => expectUpstreamReached(ctx));
        await withCert("wrong-ca", (ctx) => expectDenied495(ctx));
      } finally {
        await pomerium.stop();
      }
    });
  }
});
