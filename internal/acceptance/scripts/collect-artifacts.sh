#!/bin/bash
# Collect artifacts from E2E acceptance test run.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-${ROOT_DIR}/artifacts}"
COMPOSE_PROJECT="${COMPOSE_PROJECT:-acceptance}"
COMPOSE_FILE="${COMPOSE_FILE:-${ROOT_DIR}/docker-compose.yml}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://keycloak.localhost.pomerium.io:8080}"
POMERIUM_URL="${POMERIUM_URL:-https://authenticate.localhost.pomerium.io:8443}"

COMPOSE=(docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT")

mkdir -p "$ARTIFACTS_DIR/docker-logs" \
  "$ARTIFACTS_DIR/config" \
  "$ARTIFACTS_DIR/diagnostics" \
  "$ARTIFACTS_DIR/playwright"

services=(keycloak pomerium upstream websocket-server)

for svc in "${services[@]}"; do
  "${COMPOSE[@]}" logs --no-color "$svc" > "$ARTIFACTS_DIR/docker-logs/${svc}.log" 2>&1 || true
done
"${COMPOSE[@]}" logs --no-color > "$ARTIFACTS_DIR/docker-logs/all-services.log" 2>&1 || true

{
  echo "=== Docker Compose Status ==="
  "${COMPOSE[@]}" ps -a 2>&1 || echo "Could not get compose status"
  echo ""
  echo "=== Container Inspection ==="
  "${COMPOSE[@]}" ps -q 2>/dev/null | xargs -I{} docker inspect {} 2>&1 || echo "Could not inspect containers"
} > "$ARTIFACTS_DIR/diagnostics/containers.txt"

{
  echo "=== Network Configuration ==="
  docker network inspect "${COMPOSE_PROJECT}_acceptance" 2>&1 || echo "Could not inspect network"
} > "$ARTIFACTS_DIR/diagnostics/network.txt"

{
  echo "=== Pomerium Config (Sanitized) ==="
  if [ -f "${ROOT_DIR}/pomerium/config.yaml" ]; then
    sed -e 's/\(secret:\s*\).*/\1[REDACTED]/' \
        -e 's/\(cookie_secret:\s*\).*/\1[REDACTED]/' \
        -e 's/\(shared_secret:\s*\).*/\1[REDACTED]/' \
        -e 's/\(idp_client_secret:\s*\).*/\1[REDACTED]/' \
        "${ROOT_DIR}/pomerium/config.yaml"
  else
    echo "Config file not found"
  fi
} > "$ARTIFACTS_DIR/config/pomerium-config.txt"

{
  echo "=== /.well-known/pomerium ==="
  curl -fsSk "${POMERIUM_URL}/.well-known/pomerium" 2>&1 | sed 's/"[^"]*secret[^"]*":"[^"]*"/"secret":"[REDACTED]"/gi' || echo "Could not fetch .well-known/pomerium"
  echo ""
  echo "=== /ping ==="
  curl -fsSk "${POMERIUM_URL}/ping" 2>&1 || echo "Could not fetch /ping"
  echo ""
  echo "=== /healthz ==="
  curl -fsSk "${POMERIUM_URL}/healthz" 2>&1 || echo "Could not fetch /healthz"
} > "$ARTIFACTS_DIR/diagnostics/pomerium-endpoints.txt"

{
  echo "=== Keycloak Health ==="
  curl -fsS "${KEYCLOAK_URL}/health/ready" 2>&1 || echo "Could not fetch /health/ready"
  echo ""
  echo "=== OIDC Discovery ==="
  curl -fsS "${KEYCLOAK_URL}/realms/pomerium-e2e/.well-known/openid-configuration" 2>&1 | head -c 5000 || echo "Could not fetch OIDC discovery"
} > "$ARTIFACTS_DIR/diagnostics/keycloak-endpoints.txt"

{
  echo "=== Environment ==="
  echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "Hostname: $(hostname)"
  echo ""
  echo "=== Docker Version ==="
  docker version 2>&1 || echo "Could not get docker version"
  echo ""
  echo "=== Docker Compose Version ==="
  docker compose version 2>&1 || echo "Could not get docker compose version"
  echo ""
  echo "=== Host DNS Resolution ==="
  if command -v getent >/dev/null 2>&1; then
    for host in keycloak.localhost.pomerium.io authenticate.localhost.pomerium.io app.localhost.pomerium.io; do
      echo "$host -> $(getent hosts "$host" 2>&1 || echo 'unresolved')"
    done
  else
    echo "getent not available"
  fi
} > "$ARTIFACTS_DIR/diagnostics/environment.txt"

find "$ARTIFACTS_DIR" -type f | sort | while read -r file; do
  size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo "?")
  echo "${file#$ARTIFACTS_DIR/} (${size} bytes)"
done
