// One wildcard leaf for *.localhost.pomerium.io (+ localhost / 127.0.0.1) from
// the local mkcert CA. The browser trusts it via ignoreHTTPSErrors, so
// `mkcert -install` (which needs sudo) is deliberately not run - generating a
// cert auto-creates the CA in CAROOT, which is all we need.

import { execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { CERTS_DIR } from "./constants.js";

// In-container paths under /certs live in setup/pomerium-config.ts.
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
      `Failed to run \`mkcert ${args.join(" ")}\`. Is mkcert installed and on your PATH? ` +
        `See https://github.com/FiloSottile/mkcert#installation. Underlying error: ${(err as Error).message}`,
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
 * Ensure the leaf exists and is not about to expire. Idempotent and cheap on the
 * fast path (one file read), so any process can call it freely.
 */
export function ensureCerts(): void {
  if (leafIsFresh()) return;
  mkdirSync(CERTS_DIR, { recursive: true });
  // Generating a cert creates the local CA in CAROOT if it is missing.
  mkcert(["-cert-file", CERT_FILE, "-key-file", KEY_FILE, ...SANS]);
}
