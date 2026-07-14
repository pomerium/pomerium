// mkcert-based certificate generation.
//
// Produces ONE wildcard leaf certificate for *.localhost.pomerium.io (which
// covers mcp. and authenticate.) plus localhost / 127.0.0.1, signed by the
// local mkcert CA. Pomerium serves TLS with this leaf; the host trusts the
// mkcert root CA via NODE_EXTRA_CA_CERTS (MCP client) and Playwright's
// ignoreHTTPSErrors (browser).
//
// We deliberately do NOT run `mkcert -install` (which needs sudo to touch the
// system trust store). Generating a cert auto-creates the local CA in CAROOT if
// it does not already exist — that is all we need.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import * as path from "node:path";

export interface CertPaths {
  /** Directory holding the leaf cert+key; mounted into Pomerium at /certs. */
  certsDir: string;
  /** Leaf certificate (PEM) -> /certs/pomerium.crt. */
  certFile: string;
  /** Leaf private key (PEM) -> /certs/pomerium.key. */
  keyFile: string;
  /** mkcert root CA (PEM); point NODE_EXTRA_CA_CERTS at this. */
  caRoot: string;
}

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
 * Ensure the leaf cert/key exist and return their paths plus the CA root.
 * Idempotent: skips generation when a leaf is already present.
 */
export function ensureCerts(): CertPaths {
  const certsDir = path.resolve(__dirname, "..", ".certs");
  const certFile = path.join(certsDir, "pomerium.crt");
  const keyFile = path.join(certsDir, "pomerium.key");
  mkdirSync(certsDir, { recursive: true });

  const caRoot = path.join(mkcert(["-CAROOT"]).trim(), "rootCA.pem");

  if (!existsSync(certFile) || !existsSync(keyFile)) {
    // Generating a cert creates the local CA in CAROOT if it is missing.
    mkcert(["-cert-file", certFile, "-key-file", keyFile, ...SANS]);
  }

  if (!existsSync(caRoot)) {
    throw new Error(
      `mkcert root CA not found at ${caRoot}. Run \`mkcert -install\` once to create it.`,
    );
  }

  return { certsDir, certFile, keyFile, caRoot };
}
