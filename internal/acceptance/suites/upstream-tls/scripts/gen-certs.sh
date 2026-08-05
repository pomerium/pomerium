#!/bin/sh
# Certificate generation for the upstream TLS/mTLS e2e suite.
#
# Part 1 wraps the parent acceptance suite's server-certificate script
# (bind-mounted at /parent-scripts) so the wildcard TLS leaf Pomerium serves
# downstream has a single source of truth:
#   pomerium.crt/.key   TLS server cert for *.localhost.pomerium.io
#   ca.crt              CA that signed it
#
# Part 2 builds the upstream-side PKI under /certs/upstream/ that the tls_*
# route options are tested against:
#   upstream-ca.*            trust root for the upstream server certs (the good CA)
#   wrong-ca.*               an unrelated CA (negative tls_custom_ca case)
#   client-ca.*              trust root the mTLS upstream verifies clients against
#   server-tls.*             SAN=DNS:upstream-tls          (plain server TLS)
#   server-mtls.*            SAN=DNS:upstream-mtls         (mTLS-required upstream)
#   server-reneg.*           SAN=DNS:upstream-reneg        (renegotiation upstream)
#   server-sni-decoy.*       SAN=DNS:decoy.invalid         (SNI upstream default cert)
#   server-sni-backend.*     SAN=DNS:backend.internal.example.com (SNI-switch cert)
#   pomerium-client.*        clientAuth leaf signed by client-ca (Pomerium's cert)
#   mismatched.key           a standalone key matching no cert (cert/key-mismatch case)
#
# All upstream server certs are signed by upstream-ca; verification succeeds
# only when the route trusts upstream-ca AND the connection's verification name
# is on the presented cert. Base64 encodings for the inline tls_* surfaces are
# computed from these files at test time (helpers/fixtures.ts).
set -e

CERTS_DIR="${CERTS_DIR:-/certs}"
UP_DIR="$CERTS_DIR/upstream"
DAYS_VALID=365
export CERTS_DIR

# Bind-mounted output is written as root inside this container; make sure the
# host user (e.g. the CI runner) can read and delete everything afterwards.
trap 'chmod -R a+rwX "$CERTS_DIR" 2>/dev/null || true' EXIT

# --- Part 1: downstream server certificate (parent script) -------------------
sh /parent-scripts/gen-certs.sh

# --- Part 2: upstream PKI (idempotent, like the parent script) ---------------
# Completion marker written only after a full generation succeeds; keying the
# skip on it (not loose file existence) means an interrupted run regenerates
# rather than caching a half-written PKI. setup/certs.ts mirrors this check.
GEN_MARKER="$UP_DIR/.gen-complete"
if [ -f "$GEN_MARKER" ] \
    && openssl x509 -checkend 86400 -noout -in "$UP_DIR/server-tls.crt" 2>/dev/null; then
    echo "upstream PKI already exists and is valid, skipping generation"
    exit 0
fi

echo "Generating upstream TLS/mTLS PKI..."
mkdir -p "$UP_DIR"
rm -f "$GEN_MARKER"

# gen_ca <name> <cn> - self-signed CA (OpenSSL 3.x -addext).
gen_ca() {
    name=$1
    cn=$2
    openssl genrsa -out "$UP_DIR/$name.key" 2048 2>/dev/null
    openssl req -new -x509 -days $DAYS_VALID -key "$UP_DIR/$name.key" \
        -out "$UP_DIR/$name.crt" \
        -subj "/C=US/ST=Test/L=Test/O=Pomerium E2E/CN=$cn" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" 2>/dev/null
}

# issue_server_cert <name> <subjectAltName value> [issuer-ca-name]
# serverAuth leaf signed by the given CA (default: upstream-ca).
issue_server_cert() {
    name=$1
    san=$2
    ca=${3:-upstream-ca}
    openssl genrsa -out "$UP_DIR/$name.key" 2048 2>/dev/null
    cat > "$UP_DIR/$name-ext.cnf" << EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
subjectAltName = $san
EOF
    openssl req -new -key "$UP_DIR/$name.key" \
        -out "$UP_DIR/$name.csr" \
        -subj "/C=US/ST=Test/L=Test/O=Pomerium E2E/OU=Upstreams/CN=$name"
    openssl x509 -req -days $DAYS_VALID \
        -in "$UP_DIR/$name.csr" \
        -CA "$UP_DIR/$ca.crt" \
        -CAkey "$UP_DIR/$ca.key" \
        -CAcreateserial \
        -out "$UP_DIR/$name.crt" \
        -extfile "$UP_DIR/$name-ext.cnf" 2>/dev/null
}

# issue_client_cert <name> <cn> [issuer-ca-name]
# clientAuth leaf signed by the given CA (default: client-ca).
issue_client_cert() {
    name=$1
    cn=$2
    ca=${3:-client-ca}
    openssl genrsa -out "$UP_DIR/$name.key" 2048 2>/dev/null
    cat > "$UP_DIR/$name-ext.cnf" << EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
EOF
    openssl req -new -key "$UP_DIR/$name.key" \
        -out "$UP_DIR/$name.csr" \
        -subj "/C=US/ST=Test/L=Test/O=Pomerium E2E/OU=Clients/CN=$cn"
    openssl x509 -req -days $DAYS_VALID \
        -in "$UP_DIR/$name.csr" \
        -CA "$UP_DIR/$ca.crt" \
        -CAkey "$UP_DIR/$ca.key" \
        -CAcreateserial \
        -out "$UP_DIR/$name.crt" \
        -extfile "$UP_DIR/$name-ext.cnf" 2>/dev/null
}

gen_ca upstream-ca "Pomerium E2E Upstream CA"
gen_ca wrong-ca    "Pomerium E2E Wrong Upstream CA"
gen_ca client-ca   "Pomerium E2E Upstream Client CA"

issue_server_cert server-tls         "DNS:upstream-tls"
issue_server_cert server-mtls        "DNS:upstream-mtls"
issue_server_cert server-reneg       "DNS:upstream-reneg"
issue_server_cert server-sni-decoy   "DNS:decoy.invalid"
issue_server_cert server-sni-backend "DNS:backend.internal.example.com"

issue_client_cert pomerium-client "pomerium-client"

# Standalone key that matches no issued certificate: pairing it with
# pomerium-client.crt exercises the "cert and key do not match" config error.
openssl genrsa -out "$UP_DIR/mismatched.key" 2048 2>/dev/null

# --- Cleanup + completion marker ---------------------------------------------
rm -f "$UP_DIR"/*.csr "$UP_DIR"/*-ext.cnf
touch "$GEN_MARKER"

echo ""
echo "Upstream PKI generated:"
ls "$UP_DIR" | grep -E "\.crt$|\.key$"
