/**
 * Upstream TLS: config validation for invalid tls_* combinations.
 * Test plan: Core.Upstream TLS (cert/key must both be set; mismatched pairs;
 * missing CA file).
 *
 * Each case mounts a deliberately-invalid single-route config; Pomerium logs a
 * fatal config error on boot (config/policy.go Policy.Validate). The container
 * binds NO host port, so these never contend for 8443 with a healthy instance.
 */

import { expect, test } from "@playwright/test";
import { clientCertBase64, mismatchedKeyBase64 } from "../helpers/fixtures.js";
import { ROUTE_HOSTS, TLS_UPSTREAM_HOST, tlsUpstreamUrl } from "../setup/constants.js";
import { startPomeriumExpectingConfigError } from "../setup/containers.js";
import { CONTAINER_CERTS, generateConfig, type UpstreamTLS } from "../setup/pomerium-config.js";

/** Build a config with a single route carrying the given (invalid) tls_* options. */
function oneRouteConfig(name: string, tls: UpstreamTLS): string {
  return generateConfig({
    name,
    routes: [{ host: ROUTE_HOSTS.customCa, to: tlsUpstreamUrl(TLS_UPSTREAM_HOST), tls }],
  });
}

interface Case {
  id: string;
  title: string;
  make: () => string;
  error: RegExp;
}

const cases: Case[] = [
  {
    id: "missing-ca-file",
    title: "tls_custom_ca_file points at a nonexistent path",
    make: () => oneRouteConfig("cfg-missing-ca", { customCAFile: CONTAINER_CERTS.missingFile }),
    error: /couldn't load client ca file/,
  },
  {
    id: "cert-without-key",
    title: "tls_client_cert without tls_client_key",
    make: () => oneRouteConfig("cfg-cert-no-key", { clientCert: clientCertBase64() }),
    error: /client certificate key and cert both must be non-empty/,
  },
  {
    id: "cert-file-without-key-file",
    title: "tls_client_cert_file without tls_client_key_file",
    make: () => oneRouteConfig("cfg-certfile-no-keyfile", { clientCertFile: CONTAINER_CERTS.clientCert }),
    error: /client certificate key and cert both must be non-empty/,
  },
  {
    id: "mismatched-inline",
    title: "tls_client_cert paired with a non-matching tls_client_key",
    make: () =>
      oneRouteConfig("cfg-mismatch-inline", {
        clientCert: clientCertBase64(),
        clientKey: mismatchedKeyBase64(),
      }),
    error: /couldn't decode client cert/,
  },
  {
    id: "mismatched-file",
    title: "tls_client_cert_file paired with a non-matching tls_client_key_file",
    make: () =>
      oneRouteConfig("cfg-mismatch-file", {
        clientCertFile: CONTAINER_CERTS.clientCert,
        clientKeyFile: CONTAINER_CERTS.mismatchedKey,
      }),
    error: /couldn't load client cert file/,
  },
];

test.describe("Upstream TLS: config validation", () => {
  for (const c of cases) {
    test(`${c.id}: ${c.title} -> config error`, async () => {
      const configFile = await test.step("write the deliberately-invalid single-route config", () =>
        c.make());

      const lines = await test.step("boot a throwaway Pomerium that must refuse the config", () =>
        startPomeriumExpectingConfigError({ configFile, errorPattern: c.error }));

      await test.step(`Pomerium logged the config error (${c.error})`, () => {
        expect(
          lines.some((l) => c.error.test(l)),
          `expected a Pomerium log line matching ${c.error}\n--- captured logs ---\n${lines.join("")}`,
        ).toBe(true);
      });
    });
  }
});
