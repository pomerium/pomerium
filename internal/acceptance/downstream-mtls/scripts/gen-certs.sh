#!/bin/sh
# Certificate generation for the downstream mTLS e2e suite.
#
# Thin wrapper over the parent acceptance suite's scripts (bind-mounted at
# /parent-scripts) so the OpenSSL certificate logic has a single source of
# truth. Outputs to $CERTS_DIR:
#   pomerium.crt/.key       TLS server cert for *.localhost.pomerium.io
#   mtls/root-ca.crt        downstream_mtls trust root
#   mtls/client-valid.*     root-signed client cert (alice@company.com)
#   mtls/client-chain*.*    intermediate-signed client cert (for depth tests)
#   mtls/client-wrong-ca.*  client cert from an untrusted CA (negative tests)
set -e

CERTS_DIR="${CERTS_DIR:-/certs}"
export CERTS_DIR

# Bind-mounted output is written as root inside this container; make sure the
# host user (e.g. the CI runner) can read and delete everything afterwards.
trap 'chmod -R a+rwX "$CERTS_DIR" 2>/dev/null || true' EXIT

sh /parent-scripts/gen-certs.sh
sh /parent-scripts/gen-mtls-certs.sh
