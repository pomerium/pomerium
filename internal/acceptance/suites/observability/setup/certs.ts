// mkcert-based certificate generation (same approach as suites/mcp).
//
// Produces ONE wildcard leaf certificate for *.localhost.pomerium.io (which
// covers verify. and authenticate.) plus localhost / 127.0.0.1, signed by the
// local mkcert CA, into CERTS_DIR. Pomerium serves TLS with this leaf; the
// browser and Playwright request contexts trust it via ignoreHTTPSErrors, so
// nothing needs the CA installed.
//
// We deliberately do NOT run `mkcert -install` (which needs sudo to touch the
// system trust store). Generating a cert auto-creates the local CA in CAROOT if
// it does not already exist — that is all we need.

import { execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { CERTS_DIR } from "./constants.js";

// Leaf file names; the in-container paths under /certs live in
// setup/pomerium-config.ts, which is what puts them in the config.
const CERT_FILE = path.join(CERTS_DIR, "pomerium.crt");
const KEY_FILE = path.join(CERTS_DIR, "pomerium.key");

const SANS = [
  "*.localhost.pomerium.io",
  "localhost.pomerium.io",
  "localhost",
  "127.0.0.1",
];

function mkcert(args: string[]): string {
  try {
    return execFileSync("mkcert", args, { encoding: "utf8" });
  } catch (err) {
    throw new Error(
      `Failed to run \`mkcert ${args.join(" ")}\`. Is mkcert installed? ` +
        `(brew install mkcert). Underlying error: ${(err as Error).message}`,
    );
  }
}

/** True when the leaf exists and is valid for at least another 24h. */
function leafIsFresh(): boolean {
  if (!existsSync(CERT_FILE) || !existsSync(KEY_FILE)) return false;
  try {
    const cert = new X509Certificate(readFileSync(CERT_FILE));
    return new Date(cert.validTo).getTime() - Date.now() > 24 * 60 * 60 * 1000;
  } catch {
    return false; // unreadable/corrupt -> regenerate
  }
}

/**
 * Ensure the leaf cert/key exist in CERTS_DIR and are not about to expire.
 * Idempotent and cheap on the fast path (a file read, no subprocess), so both
 * the global-setup process and the worker can call it freely.
 */
export function ensureCerts(): void {
  if (leafIsFresh()) return;
  mkdirSync(CERTS_DIR, { recursive: true });
  // Generating a cert creates the local CA in CAROOT if it is missing.
  mkcert(["-cert-file", CERT_FILE, "-key-file", KEY_FILE, ...SANS]);
}
