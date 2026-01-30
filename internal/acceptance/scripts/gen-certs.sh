#!/bin/sh
# Generate self-signed certificates for E2E acceptance tests
# Creates a CA and wildcard certificate for *.localhost.pomerium.io

set -e

CERTS_DIR="${CERTS_DIR:-/certs}"
DOMAIN="localhost.pomerium.io"
DAYS_VALID=365

# Skip if certificates already exist and are valid
if [ -f "$CERTS_DIR/pomerium.crt" ] && [ -f "$CERTS_DIR/pomerium.key" ]; then
    # Check if cert is still valid (not expired)
    if openssl x509 -checkend 86400 -noout -in "$CERTS_DIR/pomerium.crt" 2>/dev/null; then
        echo "Certificates already exist and are valid, skipping generation"
        exit 0
    fi
fi

echo "Generating self-signed certificates for E2E tests..."

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
mkdir -p "$CERTS_DIR"

# Generate CA private key
openssl genrsa -out "$CERTS_DIR/ca.key" 4096

# Generate CA certificate
openssl req -new -x509 -days $DAYS_VALID -key "$CERTS_DIR/ca.key" \
    -out "$CERTS_DIR/ca.crt" \
    -subj "/C=US/ST=Test/L=Test/O=Pomerium E2E/CN=Pomerium E2E CA"

# Create OpenSSL config for SAN extension
cat > "$CERTS_DIR/openssl.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Test
L = Test
O = Pomerium E2E
CN = *.${DOMAIN}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = *.${DOMAIN}
DNS.2 = ${DOMAIN}
DNS.3 = authenticate.${DOMAIN}
DNS.4 = app.${DOMAIN}
DNS.5 = admin.${DOMAIN}
DNS.6 = keycloak.${DOMAIN}
DNS.7 = mtls.${DOMAIN}
DNS.8 = localhost
IP.1 = 127.0.0.1
EOF

# Generate server private key
openssl genrsa -out "$CERTS_DIR/pomerium.key" 2048

# Generate CSR
openssl req -new -key "$CERTS_DIR/pomerium.key" \
    -out "$CERTS_DIR/pomerium.csr" \
    -config "$CERTS_DIR/openssl.cnf"

# Sign the certificate with our CA
openssl x509 -req -days $DAYS_VALID \
    -in "$CERTS_DIR/pomerium.csr" \
    -CA "$CERTS_DIR/ca.crt" \
    -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERTS_DIR/pomerium.crt" \
    -extensions v3_req \
    -extfile "$CERTS_DIR/openssl.cnf"

# Clean up temporary files
rm -f "$CERTS_DIR/pomerium.csr" "$CERTS_DIR/openssl.cnf"

# Set permissions
chmod 644 "$CERTS_DIR"/*.crt "$CERTS_DIR"/*.key

echo "Certificates generated successfully:"
ls -la "$CERTS_DIR"

# Verify the certificate
echo ""
echo "Certificate details:"
openssl x509 -in "$CERTS_DIR/pomerium.crt" -noout -subject -issuer -dates
echo ""
echo "Subject Alternative Names:"
openssl x509 -in "$CERTS_DIR/pomerium.crt" -noout -ext subjectAltName
