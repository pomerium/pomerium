#!/bin/sh
# Wait for all services in the acceptance test stack to be ready.

set -e

if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is required"
    exit 1
fi

KEYCLOAK_URL="${KEYCLOAK_URL:-http://keycloak.localhost.pomerium.io:8080}"
POMERIUM_URL="${POMERIUM_URL:-https://authenticate.localhost.pomerium.io:8443}"
WEBSOCKET_URL="${WEBSOCKET_URL:-http://localhost:8081/health}"
TIMEOUT="${TIMEOUT:-120}"
INTERVAL="${INTERVAL:-2}"

start_time=$(date +%s)

check_url() {
    if [ "$2" = "true" ]; then
        curl -fsS -k "$1" >/dev/null 2>&1
    else
        curl -fsS "$1" >/dev/null 2>&1
    fi
}

wait_for() {
    name="$1"
    url="$2"
    insecure="$3"

    echo "Waiting for ${name}..."
    until check_url "$url" "$insecure"; do
        elapsed=$(($(date +%s) - start_time))
        if [ $elapsed -ge $TIMEOUT ]; then
            echo "ERROR: Timeout waiting for ${name}"
            exit 1
        fi
        sleep $INTERVAL
    done
    echo "  ${name} ready"
}

echo "Waiting for acceptance stack (timeout ${TIMEOUT}s)..."

wait_for "Keycloak" "${KEYCLOAK_URL}/realms/master" "false"
wait_for "Keycloak OIDC" "${KEYCLOAK_URL}/realms/pomerium-e2e/.well-known/openid-configuration" "false"
wait_for "Pomerium healthz" "${POMERIUM_URL}/healthz" "true"
wait_for "Pomerium ping" "${POMERIUM_URL}/ping" "true"
wait_for "Upstream" "http://localhost:8000/" "false"
wait_for "WebSocket" "${WEBSOCKET_URL}" "false"

echo "All services ready."
