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
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import * as path from "node:path";
import { certPaths } from "../helpers/mtls.js";
import { CERTS_DIR, MTLS_CERTS_DIR, SUITE_DIR } from "./constants.js";

const ACCEPTANCE_DIR = path.resolve(SUITE_DIR, "..", "..");

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

// gen-certs.sh writes this only after a full generation succeeds, recording the
// serials the CRLs were built against ("<leaf-name> <serial>" per line).
const GEN_MARKER = path.join(MTLS_CERTS_DIR, ".gen-complete");

// Revoked leaves whose serial must still match the CRLs in the cache. The
// chain-revoked leaf is the first cert of the presented full bundle.
const REVOKED_LEAVES: Record<string, string> = {
  "client-revoked": path.join(MTLS_CERTS_DIR, "client-revoked.crt"),
  "client-chain-revoked": certPaths("chain-revoked").certPath,
};

/** Normalise a serial to uppercase hex so OpenSSL and node:crypto compare equal. */
function normalizeSerial(serial: string): string {
  return serial.toUpperCase().replace(/[^0-9A-F]/g, "");
}

/** Serials the cached CRLs revoke, per the completion marker (null if absent). */
function markerSerials(): Record<string, string> | null {
  if (!existsSync(GEN_MARKER)) return null;
  const serials: Record<string, string> = {};
  for (const line of readFileSync(GEN_MARKER, "utf8").split("\n")) {
    const [name, serial] = line.trim().split(/\s+/);
    if (name && serial) serials[name] = normalizeSerial(serial);
  }
  return serials;
}

/**
 * Host-side mirror of the generation scripts' idempotence checks, so a warm
 * .certs/ directory skips the docker run entirely. ensureCerts is called once
 * per process (runner AND each worker); without this every process would
 * spawn a container just to discover there is nothing to do.
 *
 * Beyond existence + expiry, the cached CRLs must actually revoke the CURRENT
 * revoked leaves: existence alone would accept a stale CRL generated for
 * different serials (e.g. a leaf re-issued by an interrupted run, or swapped
 * out of band), silently running the revocation suite against fixtures where
 * the "revoked" cert is no longer listed.
 */
function certsAreFresh(): boolean {
  const required = [
    ...SENTINEL_CERTS,
    PATHS.keyFile,
    path.join(MTLS_CERTS_DIR, "crl-chain.pem"),
    ...Object.values(REVOKED_LEAVES),
  ];
  if (!required.every((f) => existsSync(f))) return false;

  const dayMs = 24 * 60 * 60 * 1000;
  const unexpired = SENTINEL_CERTS.every(
    (f) => new Date(new X509Certificate(readFileSync(f)).validTo).getTime() - Date.now() > dayMs,
  );
  if (!unexpired) return false;

  const expected = markerSerials();
  if (!expected) return false;
  return Object.entries(REVOKED_LEAVES).every(([name, file]) => {
    const actual = normalizeSerial(new X509Certificate(readFileSync(file)).serialNumber);
    return expected[name] === actual;
  });
}

/** Ensure all certificates exist under .certs/ and return their paths. */
export function ensureCerts(): CertPaths {
  if (certsAreFresh()) return PATHS;
  mkdirSync(CERTS_DIR, { recursive: true });
  // Drop any marker first: certsAreFresh() may have rejected the cache as
  // incoherent (serial mismatch) even though the marker exists, and the
  // container trusts its own marker to skip - so a stale one would defeat the
  // regeneration we are about to trigger.
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
