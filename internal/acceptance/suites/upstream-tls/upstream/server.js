"use strict";
// First-party TLS/mTLS echo upstream for the upstream-tls e2e suite.
//
// Dependency-free (Node core modules only) so it can be bind-mounted read-only
// into a stock node:alpine image with no install step. It terminates a REAL
// TLS handshake (OpenSSL-backed) and reports, as JSON, the facts the tls_*
// route options are asserted against:
//
//   tls.servername          the SNI Envoy sent  -> tls_server_name / tls_upstream_server_name
//   tls.authorized          client-cert verified -> tls_client_cert[_file]
//   tls.peerCertificate     the presented client cert's subject/issuer/SAN
//   claims                  request headers matching /^x-pomerium-claim-/ ONLY
//
// SECURITY: the echo is an ALLOWLIST. It never reflects Cookie, Authorization,
// the X-Pomerium-Jwt-Assertion header, or an arbitrary header dump, so no
// credential-bearing value can leak into Playwright traces / CI artifacts.
//
// Modes (env MODE): "tls" (plain server TLS), "mtls" (requires a client cert),
// "sni" (serves CERT2 when SNI == SNI_MATCH, else the default CERT), and
// "reneg" (TLS 1.2 listener that triggers server-initiated renegotiation on
// GET /reneg and reports renegotiated: true only after that second handshake
// completes). Env: PORT, CERT, KEY, CA (mtls), CERT2, KEY2, SNI_MATCH (sni).

const https = require("node:https");
const tls = require("node:tls");
const fs = require("node:fs");

const MODE = process.env.MODE || "tls";
const PORT = Number(process.env.PORT || 4433);

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`server.js: missing required env ${name} for MODE=${MODE}`);
  return value;
}

const options = {
  cert: fs.readFileSync(requireEnv("CERT")),
  key: fs.readFileSync(requireEnv("KEY")),
  // Force HTTP/1.1: Envoy offers ["h2","http/1.1"]; keep the upstream on the
  // simpler codec so assertions are about TLS, not h2 framing.
  ALPNProtocols: ["http/1.1"],
};

if (MODE === "mtls") {
  options.requestCert = true;
  options.rejectUnauthorized = true;
  options.ca = fs.readFileSync(requireEnv("CA"));
}

if (MODE === "reneg") {
  // Renegotiation is a TLS <= 1.2 concept (TLS 1.3 uses post-handshake auth);
  // pin the listener to 1.2 so the server-initiated HelloRequest is meaningful.
  options.minVersion = "TLSv1.2";
  options.maxVersion = "TLSv1.2";
}

if (MODE === "sni") {
  const matchName = requireEnv("SNI_MATCH");
  const backendCtx = tls.createSecureContext({
    cert: fs.readFileSync(requireEnv("CERT2")),
    key: fs.readFileSync(requireEnv("KEY2")),
  });
  // Serve the backend cert only for an exact SNI match; fall back to the
  // default (decoy) context otherwise.
  options.SNICallback = (servername, cb) => {
    cb(null, servername === matchName ? backendCtx : undefined);
  };
}

function claimHeaders(headers) {
  const out = {};
  for (const [key, value] of Object.entries(headers)) {
    if (/^x-pomerium-claim-/i.test(key)) {
      out[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
    }
  }
  return out;
}

function tlsInfo(socket) {
  const peer = typeof socket.getPeerCertificate === "function" ? socket.getPeerCertificate() : null;
  const hasPeer = peer && Object.keys(peer).length > 0;
  return {
    protocol: typeof socket.getProtocol === "function" ? socket.getProtocol() : null,
    cipher: typeof socket.getCipher === "function" ? (socket.getCipher() || {}).name || null : null,
    servername: socket.servername || null,
    authorized: socket.authorized === true,
    authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
    peerCertificate: hasPeer
      ? {
          subject: peer.subject || null,
          issuer: peer.issuer || null,
          subjectaltname: peer.subjectaltname || null,
        }
      : null,
  };
}

function respond(req, res, renegotiated = false) {
  const body = JSON.stringify({
    mode: MODE,
    method: req.method,
    path: req.url,
    renegotiated,
    tls: tlsInfo(req.socket),
    claims: claimHeaders(req.headers),
  });
  res.writeHead(200, { "content-type": "application/json" });
  res.end(body);
}

const server = https.createServer(options, (req, res) => {
  // reneg mode: GET /reneg forces the server to renegotiate mid-request. The
  // peer (Envoy) accepts the HelloRequest only when the route sets
  // tls_upstream_allow_renegotiation: true; otherwise it resets the connection
  // (surfaced to the client as a 5xx). Every other path responds normally.
  if (MODE === "reneg" && req.url === "/reneg") {
    const socket = req.socket;
    let initiated = false;
    try {
      initiated = socket.renegotiate({ requestCert: false, rejectUnauthorized: false }, (err) => {
        if (err) {
          try {
            socket.destroy();
          } catch {
            /* already gone */
          }
          return;
        }
        // The callback fires only after the second handshake completed, so the
        // marker is trustworthy evidence that renegotiation really happened.
        respond(req, res, true);
      });
    } catch {
      initiated = false;
    }
    // renegotiate() returns false if it could not be initiated; answer anyway
    // (renegotiated: false) so the connection is not left hanging - the spec
    // asserts the marker, so a quiet 200 cannot false-pass the positive case.
    if (initiated !== true) respond(req, res);
    return;
  }
  respond(req, res);
});

server.on("tlsClientError", (err) => {
  // Handshake-level failures (mTLS with no/invalid client cert) never become
  // HTTP requests; surface them for optional container-log assertions.
  console.log(`tlsClientError mode=${MODE}: ${err && err.message ? err.message : err}`);
});

server.listen(PORT, () => {
  console.log(`upstream-echo mode=${MODE} listening :${PORT}`);
});
