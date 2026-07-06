// Readers for certificate fixture material recorded by scripts/gen-certs.sh.

import * as fs from "node:fs";
import * as path from "node:path";
import { CERTS_DIR } from "./mtls.js";

/** Leaves for which .fp / .spki hash files are recorded. */
export type HashedLeaf = "valid" | "san-dns";

/** Lowercase SHA-256 fingerprint (PPL short form, no colons). */
export function fingerprint(leaf: HashedLeaf): string {
  return fs.readFileSync(path.join(CERTS_DIR, `client-${leaf}.fp`), "utf8").trim();
}

/** Base64-encoded SHA-256 hash of the Subject Public Key Info. */
export function spkiHash(leaf: HashedLeaf): string {
  return fs.readFileSync(path.join(CERTS_DIR, `client-${leaf}.spki`), "utf8").trim();
}

/** Base64 of the trusted root CA PEM, for the inline `ca` / DOWNSTREAM_MTLS_CA surfaces. */
export function rootCABase64(): string {
  return fs.readFileSync(path.join(CERTS_DIR, "root-ca.crt")).toString("base64");
}

/** Base64 of the root CA's CRL PEM, for the inline `crl` / DOWNSTREAM_MTLS_CRL surfaces. */
export function rootCRLBase64(): string {
  return fs.readFileSync(path.join(CERTS_DIR, "crl-root.pem")).toString("base64");
}
