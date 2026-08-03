// OpenSSL-in-a-container certificate generation.
//
// Downstream mTLS needs a full client-certificate PKI - a trusted root CA, an
// intermediate chain, and valid / untrusted-CA client certificates - which
// mkcert cannot produce. So unlike the sibling MCP suite, this one runs the
// parent acceptance suite's OpenSSL scripts in a one-shot alpine container
// (scripts/gen-certs.sh wraps them; the scripts are the single source of
// truth for the certificate material). The browser talks to Pomerium with
// ignoreHTTPSErrors, so nothing on the host needs to trust the generated CA.

import { execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { certPaths } from "../helpers/mtls.js";
import { CERTS_DIR, MTLS_CERTS_DIR, SUITE_DIR } from "./constants.js";

const ACCEPTANCE_DIR = path.resolve(SUITE_DIR, "..");

const CERTGEN_IMAGE = "alpine:3.21";

export interface CertPaths {
  /** Directory mounted read-only into Pomerium at /certs. */
  certsDir: string;
  /** Server leaf certificate/key for *.localhost.pomerium.io. */
  certFile: string;
  keyFile: string;
  /** Client-certificate PKI consumed by the specs (see helpers/mtls.ts). */
  mtlsDir: string;
}

const PATHS: CertPaths = {
  certsDir: CERTS_DIR,
  certFile: path.join(CERTS_DIR, "pomerium.crt"),
  keyFile: path.join(CERTS_DIR, "pomerium.key"),
  mtlsDir: MTLS_CERTS_DIR,
};

// One representative output per generation stage (server cert, parent mTLS
// scripts, suite-specific fixtures); expiry is checked like the scripts do
// (openssl x509 -checkend 86400).
const SENTINEL_CERTS = [
  PATHS.certFile,
  certPaths("valid").certPath,
  path.join(MTLS_CERTS_DIR, "client-san-dns.crt"),
];

/**
 * Host-side mirror of the generation scripts' idempotence checks, so a warm
 * .certs/ directory skips the docker run entirely. ensureCerts is called once
 * per process (runner AND each worker); without this every process would
 * spawn a container just to discover there is nothing to do.
 */
function certsAreFresh(): boolean {
  const required = [
    ...SENTINEL_CERTS,
    PATHS.keyFile,
    path.join(MTLS_CERTS_DIR, "crl-chain.pem"),
    certPaths("chain-revoked").certPath,
  ];
  if (!required.every((f) => existsSync(f))) return false;
  const dayMs = 24 * 60 * 60 * 1000;
  return SENTINEL_CERTS.every(
    (f) => new Date(new X509Certificate(readFileSync(f)).validTo).getTime() - Date.now() > dayMs,
  );
}

/** Ensure all certificates exist under .certs/ and return their paths. */
export function ensureCerts(): CertPaths {
  if (certsAreFresh()) return PATHS;
  mkdirSync(CERTS_DIR, { recursive: true });

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
      { encoding: "utf8", stdio: process.env.MTLS_E2E_LOGS ? "inherit" : "pipe" },
    );
  } catch (err) {
    const stderr = (err as { stderr?: string }).stderr ?? "";
    throw new Error(`certificate generation container failed: ${(err as Error).message}\n${stderr}`);
  }

  for (const f of [PATHS.certFile, PATHS.keyFile, certPaths("valid").certPath]) {
    if (!existsSync(f)) {
      throw new Error(`expected generated certificate ${f} is missing`);
    }
  }
  return PATHS;
}
