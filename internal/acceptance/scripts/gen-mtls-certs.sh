#!/bin/sh
# Generate mTLS certificates for E2E acceptance tests
# Creates Root CA, Intermediate CA, and various client certificates for testing

set -e

CERTS_DIR="${CERTS_DIR:-/certs}"
MTLS_DIR="${CERTS_DIR}/mtls"
DAYS_VALID=365

# Skip if certificates already exist and are valid
if [ -f "$MTLS_DIR/root-ca.crt" ] && [ -f "$MTLS_DIR/client-valid.crt" ]; then
    # Check if cert is still valid (not expired)
    if openssl x509 -checkend 86400 -noout -in "$MTLS_DIR/root-ca.crt" 2>/dev/null; then
        echo "mTLS certificates already exist and are valid, skipping generation"
        exit 0
    fi
fi

echo "Generating mTLS certificates for E2E tests..."

# Install openssl if not present
if ! command -v openssl >/dev/null 2>&1; then
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache openssl >/dev/null 2>&1
    else
        echo "ERROR: openssl is required"
        exit 1
    fi
fi

# Create output directory
mkdir -p "$MTLS_DIR"

# ============================================================================
# Root CA
# ============================================================================
echo "Generating Root CA..."

openssl genrsa -out "$MTLS_DIR/root-ca.key" 4096

openssl req -new -x509 -days $DAYS_VALID -key "$MTLS_DIR/root-ca.key" \
    -out "$MTLS_DIR/root-ca.crt" \
    -subj "/C=US/ST=Test/L=Test/O=Pomerium E2E/OU=mTLS Testing/CN=Pomerium E2E Root CA"

# ============================================================================
# Intermediate CA (for chain tests)
# ============================================================================
echo "Generating Intermediate CA..."

openssl genrsa -out "$MTLS_DIR/intermediate-ca.key" 4096

# Create CSR for intermediate CA
openssl req -new -key "$MTLS_DIR/intermediate-ca.key" \
    -out "$MTLS_DIR/intermediate-ca.csr" \
    -subj "/C=US/ST=Test/L=Test/O=Pomerium E2E/OU=mTLS Testing/CN=Pomerium E2E Intermediate CA"

# Create extension config for intermediate CA
cat > "$MTLS_DIR/intermediate-ca-ext.cnf" << 'EOF'
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
EOF

# Sign intermediate CA with root CA
openssl x509 -req -days $DAYS_VALID \
    -in "$MTLS_DIR/intermediate-ca.csr" \
    -CA "$MTLS_DIR/root-ca.crt" \
    -CAkey "$MTLS_DIR/root-ca.key" \
    -CAcreateserial \
    -out "$MTLS_DIR/intermediate-ca.crt" \
    -extfile "$MTLS_DIR/intermediate-ca-ext.cnf"

# Create CA chain file (intermediate + root)
cat "$MTLS_DIR/intermediate-ca.crt" "$MTLS_DIR/root-ca.crt" > "$MTLS_DIR/ca-chain.crt"

# ============================================================================
# Valid Client Certificate (signed by Root CA)
# ============================================================================
echo "Generating valid client certificate..."

openssl genrsa -out "$MTLS_DIR/client-valid.key" 2048

cat > "$MTLS_DIR/client-valid-ext.cnf" << 'EOF'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
subjectAltName = @alt_names

[alt_names]
email.1 = alice@company.com
DNS.1 = alice.company.com
EOF

openssl req -new -key "$MTLS_DIR/client-valid.key" \
    -out "$MTLS_DIR/client-valid.csr" \
    -subj "/C=US/ST=Test/L=Test/O=Pomerium E2E/OU=Clients/CN=alice/emailAddress=alice@company.com"

openssl x509 -req -days $DAYS_VALID \
    -in "$MTLS_DIR/client-valid.csr" \
    -CA "$MTLS_DIR/root-ca.crt" \
    -CAkey "$MTLS_DIR/root-ca.key" \
    -CAcreateserial \
    -out "$MTLS_DIR/client-valid.crt" \
    -extfile "$MTLS_DIR/client-valid-ext.cnf"

# Get fingerprint for policy matching
CLIENT_VALID_FP=$(openssl x509 -in "$MTLS_DIR/client-valid.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')
echo "$CLIENT_VALID_FP" > "$MTLS_DIR/client-valid.fingerprint"

# ============================================================================
# Client Certificate signed by Intermediate CA (for chain tests)
# ============================================================================
echo "Generating client certificate signed by intermediate CA..."

openssl genrsa -out "$MTLS_DIR/client-chain.key" 2048

cat > "$MTLS_DIR/client-chain-ext.cnf" << 'EOF'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
subjectAltName = @alt_names

[alt_names]
email.1 = charlie@company.com
DNS.1 = charlie.company.com
EOF

openssl req -new -key "$MTLS_DIR/client-chain.key" \
    -out "$MTLS_DIR/client-chain.csr" \
    -subj "/C=US/ST=Test/L=Test/O=Pomerium E2E/OU=Clients/CN=charlie/emailAddress=charlie@company.com"

openssl x509 -req -days $DAYS_VALID \
    -in "$MTLS_DIR/client-chain.csr" \
    -CA "$MTLS_DIR/intermediate-ca.crt" \
    -CAkey "$MTLS_DIR/intermediate-ca.key" \
    -CAcreateserial \
    -out "$MTLS_DIR/client-chain.crt" \
    -extfile "$MTLS_DIR/client-chain-ext.cnf"

# Create full chain (client + intermediate + root)
cat "$MTLS_DIR/client-chain.crt" "$MTLS_DIR/intermediate-ca.crt" > "$MTLS_DIR/client-chain-full.crt"

# ============================================================================
# Wrong CA Client Certificate (for negative tests)
# ============================================================================
echo "Generating client certificate from wrong CA..."

# Generate a completely separate CA
openssl genrsa -out "$MTLS_DIR/wrong-ca.key" 4096

openssl req -new -x509 -days $DAYS_VALID -key "$MTLS_DIR/wrong-ca.key" \
    -out "$MTLS_DIR/wrong-ca.crt" \
    -subj "/C=US/ST=Test/L=Test/O=Untrusted Corp/CN=Untrusted CA"

# Generate client cert signed by wrong CA
openssl genrsa -out "$MTLS_DIR/client-wrong-ca.key" 2048

openssl req -new -key "$MTLS_DIR/client-wrong-ca.key" \
    -out "$MTLS_DIR/client-wrong-ca.csr" \
    -subj "/C=US/ST=Test/L=Test/O=Untrusted Corp/CN=untrusted-user/emailAddress=untrusted@external.com"

cat > "$MTLS_DIR/client-wrong-ca-ext.cnf" << 'EOF'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -days $DAYS_VALID \
    -in "$MTLS_DIR/client-wrong-ca.csr" \
    -CA "$MTLS_DIR/wrong-ca.crt" \
    -CAkey "$MTLS_DIR/wrong-ca.key" \
    -CAcreateserial \
    -out "$MTLS_DIR/client-wrong-ca.crt" \
    -extfile "$MTLS_DIR/client-wrong-ca-ext.cnf"

# ============================================================================
# Cleanup
# ============================================================================
echo "Cleaning up temporary files..."
rm -f "$MTLS_DIR"/*.csr "$MTLS_DIR"/*.cnf

# Set permissions (test-only: keep readable by CI runner)
chmod 644 "$MTLS_DIR"/*.crt 2>/dev/null || true
chmod 644 "$MTLS_DIR"/*.key 2>/dev/null || true

echo ""
echo "mTLS certificates generated successfully:"
ls -la "$MTLS_DIR"

echo ""
echo "Certificate details:"
echo "===================="
echo ""
echo "Root CA:"
openssl x509 -in "$MTLS_DIR/root-ca.crt" -noout -subject -issuer
echo ""
echo "Valid client cert fingerprint (SHA256):"
cat "$MTLS_DIR/client-valid.fingerprint"
