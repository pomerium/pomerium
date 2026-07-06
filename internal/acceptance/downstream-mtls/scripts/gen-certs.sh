#!/bin/sh
# Certificate generation for the downstream mTLS e2e suite.
#
# Part 1 wraps the parent acceptance suite's scripts (bind-mounted at
# /parent-scripts) so the base OpenSSL certificate logic has a single source
# of truth:
#   pomerium.crt/.key       TLS server cert for *.localhost.pomerium.io
#   mtls/root-ca.crt        downstream_mtls trust root
#   mtls/client-valid.*     root-signed client cert (alice@company.com)
#   mtls/client-chain*.*    intermediate-signed client cert (depth tests)
#   mtls/client-wrong-ca.*  client cert from an untrusted CA (negative tests)
#
# Part 2 adds suite-specific fixtures for the Client Certificates test plan:
#   mtls/client-san-{dns,email,ip,uri}.*  one SAN type each (match_subject_alt_names)
#   mtls/client-san-mismatch.*            SANs matching no configured pattern
#   mtls/client-revoked.* + mtls/crl-root.pem        CRL / revocation tests
#   mtls/crl-intermediate.pem                        empty CRL (full-chain CRL cases)
#   mtls/<leaf>.fp / mtls/<leaf>.spki     lowercase SHA-256 fingerprint / base64
#                                         SPKI hash for PPL + header assertions
set -e

CERTS_DIR="${CERTS_DIR:-/certs}"
MTLS_DIR="$CERTS_DIR/mtls"
DAYS_VALID=365
export CERTS_DIR

# Bind-mounted output is written as root inside this container; make sure the
# host user (e.g. the CI runner) can read and delete everything afterwards.
trap 'chmod -R a+rwX "$CERTS_DIR" 2>/dev/null || true' EXIT

sh /parent-scripts/gen-certs.sh
sh /parent-scripts/gen-mtls-certs.sh

# ============================================================================
# Suite-specific fixtures (idempotent, like the parent scripts)
# ============================================================================
if [ -f "$MTLS_DIR/client-san-dns.crt" ] && [ -f "$MTLS_DIR/crl-chain.pem" ] \
    && [ -f "$MTLS_DIR/client-chain-revoked-full.crt" ] \
    && openssl x509 -checkend 86400 -noout -in "$MTLS_DIR/client-san-dns.crt" 2>/dev/null; then
    echo "suite-specific mTLS fixtures already exist and are valid, skipping generation"
    exit 0
fi

echo "Generating suite-specific mTLS fixtures..."

# issue_client_cert <name> <cn> <subjectAltName value> [issuer-ca-name]
# Issues a clientAuth leaf signed by the given CA (default: root CA).
issue_client_cert() {
    name=$1
    cn=$2
    san=$3
    ca=${4:-root-ca}

    openssl genrsa -out "$MTLS_DIR/$name.key" 2048 2>/dev/null

    cat > "$MTLS_DIR/$name-ext.cnf" << EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
subjectAltName = $san
EOF

    openssl req -new -key "$MTLS_DIR/$name.key" \
        -out "$MTLS_DIR/$name.csr" \
        -subj "/C=US/ST=Test/L=Test/O=Pomerium E2E/OU=Clients/CN=$cn"

    openssl x509 -req -days $DAYS_VALID \
        -in "$MTLS_DIR/$name.csr" \
        -CA "$MTLS_DIR/$ca.crt" \
        -CAkey "$MTLS_DIR/$ca.key" \
        -CAcreateserial \
        -out "$MTLS_DIR/$name.crt" \
        -extfile "$MTLS_DIR/$name-ext.cnf" 2>/dev/null
}

# write_hashes <name>
# Records the leaf's lowercase SHA-256 fingerprint (PPL short form) and its
# base64-encoded SHA-256 SPKI hash, exactly as the docs' openssl commands do.
write_hashes() {
    name=$1
    openssl x509 -in "$MTLS_DIR/$name.crt" -noout -fingerprint -sha256 \
        | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f' > "$MTLS_DIR/$name.fp"
    openssl x509 -in "$MTLS_DIR/$name.crt" -noout -pubkey \
        | openssl pkey -pubin -outform DER \
        | openssl dgst -sha256 -binary \
        | openssl enc -base64 > "$MTLS_DIR/$name.spki"
}

# --- SAN-variant client certificates (match_subject_alt_names tests) --------
issue_client_cert client-san-dns      san-dns      "DNS:client.san-test.example"
issue_client_cert client-san-email    san-email    "email:san-user@san-test.example"
issue_client_cert client-san-ip       san-ip       "IP:10.99.1.1"
issue_client_cert client-san-uri      san-uri      "URI:spiffe://san-test.example/client"
issue_client_cert client-san-mismatch san-mismatch "DNS:nomatch.other.example"

# --- Revoked client certificates + CRLs ---------------------------------------
issue_client_cert client-revoked revoked-user "email:revoked@san-test.example"

# Intermediate-signed leaf revoked by ITS issuer's CRL (Pomerium consults the
# CRL of the leaf's direct issuer only - see authorize/evaluator/functions.go).
issue_client_cert client-chain-revoked chain-revoked "email:chain-revoked@san-test.example" intermediate-ca
cat "$MTLS_DIR/client-chain-revoked.crt" "$MTLS_DIR/intermediate-ca.crt" > "$MTLS_DIR/client-chain-revoked-full.crt"

# gen_crl <ca-name> <out-file> [cert-to-revoke]
# openssl's CRL commands need the `openssl ca` database machinery.
gen_crl() {
    ca=$1
    out=$2
    revoke=$3
    db="$CERTS_DIR/.crl-db/$ca"

    mkdir -p "$db"
    : > "$db/index.txt"
    echo 1000 > "$db/crlnumber"
    cat > "$db/ca.cnf" << EOF
[ca]
default_ca = CA_default
[CA_default]
database = $db/index.txt
crlnumber = $db/crlnumber
default_md = sha256
default_crl_days = 3650
EOF

    if [ -n "$revoke" ]; then
        openssl ca -config "$db/ca.cnf" \
            -keyfile "$MTLS_DIR/$ca.key" -cert "$MTLS_DIR/$ca.crt" \
            -revoke "$revoke" 2>/dev/null
    fi
    openssl ca -config "$db/ca.cnf" \
        -keyfile "$MTLS_DIR/$ca.key" -cert "$MTLS_DIR/$ca.crt" \
        -gencrl -out "$out" 2>/dev/null
}

gen_crl root-ca         "$MTLS_DIR/crl-root.pem" "$MTLS_DIR/client-revoked.crt"
gen_crl intermediate-ca "$MTLS_DIR/crl-intermediate.pem" "$MTLS_DIR/client-chain-revoked.crt"

# CRL bundle covering the whole root -> intermediate chain (client-revoked is
# revoked by the root's CRL, client-chain-revoked by the intermediate's).
cat "$MTLS_DIR/crl-root.pem" "$MTLS_DIR/crl-intermediate.pem" > "$MTLS_DIR/crl-chain.pem"

# --- Hash material for PPL / header assertions -------------------------------
write_hashes client-valid
write_hashes client-san-dns

# --- Cleanup ------------------------------------------------------------------
rm -f "$MTLS_DIR"/client-san-*.csr "$MTLS_DIR"/client-san-*-ext.cnf \
      "$MTLS_DIR"/client-revoked.csr "$MTLS_DIR"/client-revoked-ext.cnf \
      "$MTLS_DIR"/client-chain-revoked.csr "$MTLS_DIR"/client-chain-revoked-ext.cnf

echo ""
echo "Suite-specific fixtures generated:"
ls "$MTLS_DIR" | grep -E "san|revoked|crl|\.fp$|\.spki$"
