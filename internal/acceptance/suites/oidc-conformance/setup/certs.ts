// mkcert-based certificate generation.
//
// Produces ONE wildcard leaf certificate for *.localhost.pomerium.io (which
// covers conformance. and authenticate.) plus localhost / 127.0.0.1, signed by
// the local mkcert CA. Pomerium serves TLS with this leaf; the browser relies on
// Playwright's ignoreHTTPSErrors.
//
// We deliberately do NOT run `mkcert -install` (which needs sudo to touch the
// system trust store). Generating a cert auto-creates the local CA in CAROOT if
// it does not already exist — that is all we need.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import * as path from "node:path";

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

/**
 * Ensure the leaf cert (pomerium.crt) and key (pomerium.key) exist, and return
 * the directory holding them, which is mounted into Pomerium at /certs.
 * Idempotent: skips generation when a leaf is already present.
 */
export function ensureCerts(): string {
  const certsDir = path.resolve(__dirname, "..", ".certs");
  const certFile = path.join(certsDir, "pomerium.crt");
  const keyFile = path.join(certsDir, "pomerium.key");
  mkdirSync(certsDir, { recursive: true });

  if (!existsSync(certFile) || !existsSync(keyFile)) {
    // Generating a cert creates the local CA in CAROOT if it is missing.
    mkcert(["-cert-file", certFile, "-key-file", keyFile, ...SANS]);
  }
  return certsDir;
}
