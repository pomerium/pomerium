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

// gen-certs.sh writes this only after a full generation succeeds; its existence
// is the completion sentinel (the container keys its own skip on it too).
const GEN_MARKER = path.join(MTLS_CERTS_DIR, ".gen-complete");

// Revoked leaves paired with the CRLs that must actually list them: each leaf's
// direct-issuer CRL plus the chain bundle the full-chain specs consume. The
// chain-revoked leaf is the first cert of the presented full bundle.
interface RevokedFixture {
  leaf: string;
  crls: string[];
}
const REVOKED_FIXTURES: RevokedFixture[] = [
  {
    leaf: path.join(MTLS_CERTS_DIR, "client-revoked.crt"),
    crls: [
      path.join(MTLS_CERTS_DIR, "crl-root.pem"),
      path.join(MTLS_CERTS_DIR, "crl-chain.pem"),
    ],
  },
  {
    leaf: certPaths("chain-revoked").certPath,
    crls: [
      path.join(MTLS_CERTS_DIR, "crl-intermediate.pem"),
      path.join(MTLS_CERTS_DIR, "crl-chain.pem"),
    ],
  },
];

/** Uppercase hex with leading zeros stripped, so OpenSSL/DER and node:crypto compare equal. */
function canonicalSerial(hex: string): string {
  return hex.toUpperCase().replace(/[^0-9A-F]/g, "").replace(/^0+/, "") || "0";
}

/** One ASN.1 DER TLV: its tag and the byte offsets of its value and its successor. */
function readTLV(der: Buffer, pos: number): { tag: number; valueStart: number; valueEnd: number; end: number } {
  const tag = der[pos];
  let i = pos + 1;
  let len = der[i++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let k = 0; k < n; k++) len = (len << 8) | der[i++];
  }
  return { tag, valueStart: i, valueEnd: i + len, end: i + len };
}

/**
 * Serials revoked by every CRL in a (possibly multi-CRL) PEM file, parsed
 * directly from the DER rather than trusted from marker metadata. Walks the
 * RFC 5280 TBSCertList positionally to the optional revokedCertificates
 * SEQUENCE and collects each entry's userCertificate serial.
 */
function crlRevokedSerials(file: string): Set<string> {
  const serials = new Set<string>();
  const pem = readFileSync(file, "utf8");
  for (const [, body] of pem.matchAll(/-----BEGIN X509 CRL-----([\s\S]*?)-----END X509 CRL-----/g)) {
    const der = Buffer.from(body.replace(/\s+/g, ""), "base64");
    const tbs = readTLV(der, readTLV(der, 0).valueStart); // CertificateList -> TBSCertList
    let pos = tbs.valueStart;
    if (der[pos] === 0x02) pos = readTLV(der, pos).end; // version (optional)
    pos = readTLV(der, pos).end; // signature AlgorithmIdentifier
    pos = readTLV(der, pos).end; // issuer Name
    pos = readTLV(der, pos).end; // thisUpdate
    if (pos < tbs.valueEnd && (der[pos] === 0x17 || der[pos] === 0x18)) {
      pos = readTLV(der, pos).end; // nextUpdate (optional)
    }
    // revokedCertificates is an optional SEQUENCE here; a [0] tag (0xA0) in its
    // place is crlExtensions, i.e. a CRL that revokes nothing.
    if (pos < tbs.valueEnd && der[pos] === 0x30) {
      const revoked = readTLV(der, pos);
      for (let rp = revoked.valueStart; rp < revoked.valueEnd; ) {
        const entry = readTLV(der, rp); // per-entry SEQUENCE
        const serial = readTLV(der, entry.valueStart); // userCertificate INTEGER
        serials.add(canonicalSerial(der.subarray(serial.valueStart, serial.valueEnd).toString("hex")));
        rp = entry.end;
      }
    }
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
 * revoked leaves. We compare the leaf serial against the CRLs parsed from disk,
 * not against the marker: trusting the marker's recorded serials would accept a
 * cache whose CRLs were swapped for valid ones omitting those leaves (or a leaf
 * re-issued out of band), silently running the revocation suite against
 * fixtures where the "revoked" cert is no longer listed.
 */
function certsAreFresh(): boolean {
  const required = [
    ...SENTINEL_CERTS,
    PATHS.keyFile,
    ...REVOKED_FIXTURES.flatMap(({ leaf, crls }) => [leaf, ...crls]),
  ];
  if (!required.every((f) => existsSync(f))) return false;
  if (!existsSync(GEN_MARKER)) return false;

  const dayMs = 24 * 60 * 60 * 1000;
  const unexpired = SENTINEL_CERTS.every(
    (f) => new Date(new X509Certificate(readFileSync(f)).validTo).getTime() - Date.now() > dayMs,
  );
  if (!unexpired) return false;

  return REVOKED_FIXTURES.every(({ leaf, crls }) => {
    const serial = canonicalSerial(new X509Certificate(readFileSync(leaf)).serialNumber);
    return crls.every((crl) => crlRevokedSerials(crl).has(serial));
  });
}

/** Ensure all certificates exist under .certs/ and return their paths. */
export function ensureCerts(): CertPaths {
  if (certsAreFresh()) return PATHS;
  mkdirSync(CERTS_DIR, { recursive: true });
  // Drop any marker first: certsAreFresh() may have rejected the cache as
  // incoherent (a CRL that no longer lists the revoked leaf) even though the
  // marker exists, and the container trusts its own marker to skip - so a stale
  // one would defeat the regeneration we are about to trigger.
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
