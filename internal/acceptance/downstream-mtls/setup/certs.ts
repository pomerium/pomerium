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
import { existsSync, mkdirSync } from "node:fs";
import * as path from "node:path";

const SETUP_DIR = __dirname;
const SUITE_DIR = path.resolve(SETUP_DIR, "..");
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

/**
 * Ensure all certificates exist under .certs/ and return their paths.
 * Idempotent: the wrapped scripts skip generation while existing certificates
 * are still valid, so running the container on every boot is cheap.
 */
export function ensureCerts(): CertPaths {
  const certsDir = path.join(SUITE_DIR, ".certs");
  const certs: CertPaths = {
    certsDir,
    certFile: path.join(certsDir, "pomerium.crt"),
    keyFile: path.join(certsDir, "pomerium.key"),
    mtlsDir: path.join(certsDir, "mtls"),
  };
  mkdirSync(certsDir, { recursive: true });

  try {
    execFileSync(
      "docker",
      [
        "run",
        "--rm",
        "-v", `${path.join(SUITE_DIR, "scripts")}:/scripts:ro`,
        "-v", `${path.join(ACCEPTANCE_DIR, "scripts")}:/parent-scripts:ro`,
        "-v", `${certsDir}:/certs`,
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

  for (const f of [certs.certFile, certs.keyFile, path.join(certs.mtlsDir, "client-valid.crt")]) {
    if (!existsSync(f)) {
      throw new Error(`expected generated certificate ${f} is missing`);
    }
  }
  return certs;
}
