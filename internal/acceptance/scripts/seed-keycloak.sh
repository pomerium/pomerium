#!/bin/bash
# Seed Keycloak with test users for E2E acceptance tests
# Creates ephemeral users with run-specific prefixes for isolation

set -e

# Check required dependencies
for cmd in curl jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command '$cmd' not found."
        echo "Install with: brew install $cmd (macOS) or apt-get install $cmd (Ubuntu)"
        exit 1
    fi
done

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://keycloak.localhost.pomerium.io:8080}"
REALM="${REALM:-pomerium-e2e}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
RUN_ID="${RUN_ID:-default}"

# Test user definitions (single source of truth)
# Source of truth: internal/acceptance/fixtures/users.json
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USERS_FILE="${USERS_FILE:-${SCRIPT_DIR}/../fixtures/users.json}"

if [ ! -f "$USERS_FILE" ]; then
    echo "ERROR: Users fixture not found at $USERS_FILE"
    echo "Expected: internal/acceptance/fixtures/users.json"
    exit 1
fi

# Format: username:email:password:groups:department
USERS=()
while IFS= read -r user_def; do
    if [ -n "$user_def" ]; then
        USERS+=("$user_def")
    fi
done < <(
    jq -r '.users[] | "\(.username):\(.email):\(.password):\(.groups | join(",")):\(.department)"' "$USERS_FILE"
)

if [ "${#USERS[@]}" -eq 0 ]; then
    echo "ERROR: No users found in $USERS_FILE"
    exit 1
fi

echo "Seeding Keycloak with test users..."
echo "Keycloak URL: $KEYCLOAK_URL"
echo "Realm: $REALM"
echo "Run ID: $RUN_ID"

# Get admin access token
echo ""
echo "Authenticating with admin-cli..."
TOKEN_RESPONSE=$(curl -fsS -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${ADMIN_USER}" \
    -d "password=${ADMIN_PASSWORD}" \
    -d "grant_type=password" \
    -d "client_id=admin-cli")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')

if [ -z "$ACCESS_TOKEN" ]; then
    echo "ERROR: Failed to get admin access token"
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi
echo "Admin authentication successful"

# Configure user profile to allow department attribute
echo ""
echo "Configuring user profile to allow department attribute..."
CURRENT_PROFILE=$(curl -fsS "${KEYCLOAK_URL}/admin/realms/${REALM}/users/profile" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

# Check if department attribute already exists
if echo "$CURRENT_PROFILE" | jq -e '.attributes[]? | select(.name == "department")' >/dev/null; then
    echo "  Department attribute already configured"
else
    echo "  Adding department attribute to user profile..."
    UPDATED_PROFILE=$(echo "$CURRENT_PROFILE" | jq '.attributes += [{
        "name": "department",
        "displayName": "Department",
        "permissions": {
            "view": ["admin", "user"],
            "edit": ["admin"]
        },
        "multivalued": false
    }]')

    curl -fsS -X PUT "${KEYCLOAK_URL}/admin/realms/${REALM}/users/profile" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$UPDATED_PROFILE" > /dev/null
    echo "  User profile updated"
fi

# Function to get group ID by name
get_group_id() {
    local group_name="$1"
    curl -fsS "${KEYCLOAK_URL}/admin/realms/${REALM}/groups" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        | jq -r --arg name "$group_name" '.[] | select(.name == $name) | .id' \
        | head -1
}

# Function to create a user
create_user() {
    local username="$1"
    local email="$2"
    local password="$3"
    local groups="$4"
    local department="$5"

    local prefixed_username="test-user-${RUN_ID}-${username}"
    local first_name=$(echo "$username" | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')

    echo ""
    echo "Creating user: $prefixed_username (email: $email)"

    # Create user JSON
    local user_json="{\"username\":\"${prefixed_username}\",\"email\":\"${email}\",\"emailVerified\":true,\"enabled\":true,\"firstName\":\"${first_name}\",\"lastName\":\"TestUser\",\"attributes\":{\"department\":[\"${department}\"]},\"credentials\":[{\"type\":\"password\",\"value\":\"${password}\",\"temporary\":false}]}"

    # Create the user
    local http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/users" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$user_json")

    if [ "$http_code" = "201" ]; then
        echo "  User created successfully"
    elif [ "$http_code" = "409" ]; then
        echo "  User already exists, skipping creation"
    else
        echo "  WARNING: Unexpected response: $http_code"
    fi

    # Get user ID
    local user_id=$(curl -fsS "${KEYCLOAK_URL}/admin/realms/${REALM}/users?username=${prefixed_username}&exact=true" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        | jq -r '.[0].id // empty')

    if [ -z "$user_id" ]; then
        echo "  ERROR: Could not get user ID"
        return 1
    fi
    echo "  User ID: $user_id"

    # Assign groups
    IFS=',' read -ra GROUP_ARRAY <<< "$groups"
    for group in "${GROUP_ARRAY[@]}"; do
        local group_id=$(get_group_id "$group")
        if [ -n "$group_id" ]; then
            echo "  Adding to group: $group (ID: $group_id)"
            curl -fsS -X PUT "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${user_id}/groups/${group_id}" \
                -H "Authorization: Bearer $ACCESS_TOKEN" || echo "    WARNING: Failed to add to group"
        else
            echo "  WARNING: Group not found: $group"
        fi
    done

    echo "  User setup complete"
}

# Function to remove user from a group
remove_from_group() {
    local username="$1"
    local group="$2"

    local prefixed_username="test-user-${RUN_ID}-${username}"

    echo ""
    echo "Removing user $prefixed_username from group $group..."

    # Get user ID
    local user_id=$(curl -fsS "${KEYCLOAK_URL}/admin/realms/${REALM}/users?username=${prefixed_username}&exact=true" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        | jq -r '.[0].id // empty')

    if [ -z "$user_id" ]; then
        echo "  ERROR: User not found"
        return 1
    fi

    # Get group ID
    local group_id=$(get_group_id "$group")
    if [ -z "$group_id" ]; then
        echo "  ERROR: Group not found"
        return 1
    fi

    # Remove from group
    curl -fsS -X DELETE "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${user_id}/groups/${group_id}" \
        -H "Authorization: Bearer $ACCESS_TOKEN"

    echo "  User removed from group"
}

# Function to cleanup users by prefix
cleanup_users() {
    local prefix="${1:-test-user-${RUN_ID}}"

    echo ""
    echo "Cleaning up users with prefix: $prefix"

    local users=$(curl -fsS "${KEYCLOAK_URL}/admin/realms/${REALM}/users?search=${prefix}&max=100" \
        -H "Authorization: Bearer $ACCESS_TOKEN")

    local user_ids=$(echo "$users" | jq -r '.[].id')

    for user_id in $user_ids; do
        echo "  Deleting user: $user_id"
        curl -fsS -X DELETE "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${user_id}" \
            -H "Authorization: Bearer $ACCESS_TOKEN" || echo "    WARNING: Failed to delete"
    done

    echo "  Cleanup complete"
}

# Main execution
case "${1:-seed}" in
    seed)
        for user_def in "${USERS[@]}"; do
            IFS=':' read -r username email password groups department <<< "$user_def"
            create_user "$username" "$email" "$password" "$groups" "$department"
        done
        echo ""
        echo "============================================"
        echo "Keycloak seeding complete!"
        echo "============================================"
        echo ""
        echo "Created users:"
        for user_def in "${USERS[@]}"; do
            IFS=':' read -r username email password groups department <<< "$user_def"
            echo "  - test-user-${RUN_ID}-${username} (email: ${email}, groups: ${groups})"
        done
        ;;
    remove-from-group)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 remove-from-group <username> <group>"
            exit 1
        fi
        remove_from_group "$2" "$3"
        ;;
    cleanup)
        cleanup_users "${2:-test-user-${RUN_ID}}"
        ;;
    *)
        echo "Usage: $0 {seed|remove-from-group|cleanup} [args...]"
        exit 1
        ;;
esac
