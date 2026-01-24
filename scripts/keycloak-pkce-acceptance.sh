#!/usr/bin/env bash
set -euo pipefail

# Run PKCE acceptance tests against a real Keycloak instance.
#
# Usage:
#   ./scripts/keycloak-pkce-acceptance.sh
#
# Prerequisites: docker compose, go

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/acceptance/docker-compose.yaml"

cleanup() {
  docker compose -f "${COMPOSE_FILE}" down -v 2>/dev/null || true
}
trap cleanup EXIT

cleanup
docker compose -f "${COMPOSE_FILE}" up -d --wait
echo "keycloak ready"
sleep 2

export KEYCLOAK_URL="http://localhost:8080"
export KEYCLOAK_REALM="pomerium"
export KEYCLOAK_CLIENT_ID="pomerium"
export KEYCLOAK_CLIENT_SECRET="pomerium-secret"
export KEYCLOAK_USERNAME="testuser"
export KEYCLOAK_PASSWORD="testpassword"
export KEYCLOAK_REDIRECT_URI="http://localhost:5555/callback"
export KEYCLOAK_SCOPES="openid profile email"

go test ./acceptance -tags acceptance -run TestKeycloakPKCE -v -count=1
