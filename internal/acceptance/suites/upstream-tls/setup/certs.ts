// OpenSSL-in-a-container certificate generation.
//
// The upstream TLS/mTLS PKI (root CAs, server leaves with specific SANs, a
// client leaf) is built by scripts/gen-certs.sh in a one-shot alpine container
// that also wraps the parent suite's server-cert script (the single source of
// truth for the downstream wildcard leaf). Nothing on the host needs to trust
// the generated CAs: the browser talks to Pomerium with ignoreHTTPSErrors, and
// each route tells Pomerium which upstream CA to trust via tls_custom_ca.

import { execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
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

// Every file the specs / config generator rely on. Existence gates the docker
// run; expiry is checked on the certs like the scripts do (x509 -checkend).
const REQUIRED_CERTS = [
  PATHS.certFile,
  up("upstream-ca.crt"),
  up("wrong-ca.crt"),
  up("client-ca.crt"),
  up("server-tls.crt"),
  up("server-mtls.crt"),
  up("server-reneg.crt"),
  up("server-sni-decoy.crt"),
  up("server-sni-backend.crt"),
  up("pomerium-client.crt"),
];
const REQUIRED_KEYS = [
  PATHS.keyFile,
  up("upstream-ca.key"),
  up("wrong-ca.key"),
  up("client-ca.key"),
  up("server-tls.key"),
  up("server-mtls.key"),
  up("server-reneg.key"),
  up("server-sni-decoy.key"),
  up("server-sni-backend.key"),
  up("pomerium-client.key"),
  up("mismatched.key"),
];

/**
 * Host-side mirror of the script's idempotence check so a warm .certs/ skips
 * the docker run entirely. ensureCerts is called once per process (runner AND
 * each worker); without this every process would spawn a container just to
 * discover there is nothing to do.
 */
function certsAreFresh(): boolean {
  if (!existsSync(GEN_MARKER)) return false;
  if (![...REQUIRED_CERTS, ...REQUIRED_KEYS].every((f) => existsSync(f))) return false;

  const dayMs = 24 * 60 * 60 * 1000;
  return REQUIRED_CERTS.every(
    (f) => new Date(new X509Certificate(readFileSync(f)).validTo).getTime() - Date.now() > dayMs,
  );
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
