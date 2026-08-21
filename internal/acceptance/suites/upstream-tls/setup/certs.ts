// OpenSSL-in-a-container certificate generation.
//
// The upstream TLS/mTLS PKI (root CAs, server leaves with specific SANs, a
// client leaf) is built by scripts/gen-certs.sh in a one-shot alpine container
// that also wraps the parent suite's server-cert script (the single source of
// truth for the downstream wildcard leaf). Nothing on the host needs to trust
// the generated CAs: the browser talks to Pomerium with ignoreHTTPSErrors, and
// each route tells Pomerium which upstream CA to trust via tls_custom_ca.

import { execFileSync } from "node:child_process";
import { createPrivateKey, X509Certificate } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import * as path from "node:path";
import { CERTS_DIR, SUITE_DIR, UPSTREAM_CERTS_DIR } from "./constants.js";

const ACCEPTANCE_DIR = path.resolve(SUITE_DIR, "..", "..");
const CERTGEN_IMAGE = "alpine:3.21";
const LOGS = !!process.env.UPSTREAM_TLS_E2E_LOGS;

export interface CertPaths {
  /** Directory mounted read-only into Pomerium (and the upstreams) at /certs. */
  certsDir: string;
  /** Downstream server leaf certificate/key for *.localhost.pomerium.io. */
  certFile: string;
  keyFile: string;
  /** Upstream-side PKI directory consumed by the specs / config generator. */
  upstreamDir: string;
}

const PATHS: CertPaths = {
  certsDir: CERTS_DIR,
  certFile: path.join(CERTS_DIR, "pomerium.crt"),
  keyFile: path.join(CERTS_DIR, "pomerium.key"),
  upstreamDir: UPSTREAM_CERTS_DIR,
};

const up = (name: string): string => path.join(UPSTREAM_CERTS_DIR, name);

// gen-certs.sh writes this only after a full generation succeeds; its existence
// is the completion sentinel (the container keys its own skip on it too).
const GEN_MARKER = up(".gen-complete");

// Every file the specs / config generator rely on, as cert/key pairs so the
// freshness check can verify each cached key still parses and matches its
// certificate (not just that a file exists at the path).
const CERT_KEY_PAIRS: ReadonlyArray<readonly [cert: string, key: string]> = [
  [PATHS.certFile, PATHS.keyFile],
  [up("upstream-ca.crt"), up("upstream-ca.key")],
  [up("wrong-ca.crt"), up("wrong-ca.key")],
  [up("client-ca.crt"), up("client-ca.key")],
  [up("server-tls.crt"), up("server-tls.key")],
  [up("server-mtls.crt"), up("server-mtls.key")],
  [up("server-reneg.crt"), up("server-reneg.key")],
  [up("server-sni-decoy.crt"), up("server-sni-decoy.key")],
  [up("server-sni-backend.crt"), up("server-sni-backend.key")],
  [up("pomerium-client.crt"), up("pomerium-client.key")],
];
// Standalone key that deliberately matches no cert (config-validation's
// cert/key-mismatch case pairs it with pomerium-client.crt).
const MISMATCHED_KEY = up("mismatched.key");
const PAIRED_WITH_MISMATCHED_KEY = up("pomerium-client.crt");

/**
 * Host-side mirror of the script's idempotence check so a warm .certs/ skips
 * the docker run entirely. ensureCerts is called once per process (runner AND
 * each worker); without this every process would spawn a container just to
 * discover there is nothing to do.
 */
function certsAreFresh(): boolean {
  if (!existsSync(GEN_MARKER)) return false;
  if (![...CERT_KEY_PAIRS.flat(), MISMATCHED_KEY].every((f) => existsSync(f))) return false;

  const dayMs = 24 * 60 * 60 * 1000;
  try {
    for (const [certFile, keyFile] of CERT_KEY_PAIRS) {
      const cert = new X509Certificate(readFileSync(certFile));
      if (new Date(cert.validTo).getTime() - Date.now() <= dayMs) return false;
      // A cached key that no longer parses or no longer matches its cert
      // would pass an existence check but fail Pomerium / the echo upstreams
      // at TLS init.
      if (!cert.checkPrivateKey(createPrivateKey(readFileSync(keyFile)))) return false;
    }
    // The mismatch fixture must still parse as a key AND still not match the
    // cert config-validation pairs it with, or that suite would run against a
    // cache that no longer reproduces the mismatch.
    const mismatched = createPrivateKey(readFileSync(MISMATCHED_KEY));
    return !new X509Certificate(readFileSync(PAIRED_WITH_MISMATCHED_KEY)).checkPrivateKey(mismatched);
  } catch {
    // An unreadable or malformed cached certificate/key means "not fresh":
    // fall through to regeneration instead of aborting setup.
    return false;
  }
}

/** Ensure all certificates exist under .certs/ and return their paths. */
export function ensureCerts(): CertPaths {
  if (certsAreFresh()) return PATHS;
  mkdirSync(UPSTREAM_CERTS_DIR, { recursive: true });
  // Drop any marker first: the container trusts its own marker to skip, so a
  // stale one would defeat the regeneration we are about to trigger.
  rmSync(GEN_MARKER, { force: true });

  try {
    execFileSync(
      "docker",
      [
        "run",
        "--rm",
        "-v", `${path.join(SUITE_DIR, "scripts")}:/scripts:ro`,
        "-v", `${path.join(ACCEPTANCE_DIR, "scripts")}:/parent-scripts:ro`,
        "-v", `${CERTS_DIR}:/certs`,
        CERTGEN_IMAGE,
        "/bin/sh",
        "/scripts/gen-certs.sh",
      ],
      { encoding: "utf8", stdio: LOGS ? "inherit" : "pipe" },
    );
  } catch (err) {
    const stderr = (err as { stderr?: string }).stderr ?? "";
    throw new Error(`certificate generation container failed: ${(err as Error).message}\n${stderr}`);
  }

  for (const f of [PATHS.certFile, PATHS.keyFile, up("server-tls.crt"), up("pomerium-client.crt")]) {
    if (!existsSync(f)) throw new Error(`expected generated certificate ${f} is missing`);
  }
  return PATHS;
}
