/**
 * Shared test-user fixtures for the container-based acceptance suites
 * (suites/mcp, suites/downstream-mtls).
 *
 * Single source of truth for the suites under suites/, decoupled from the
 * browser suite. suites/shared sits at the same depth below internal/acceptance/
 * as browser/fixtures did, so the realm-JSON path below is unchanged.
 *
 * Only the fields the container suites actually use (username, email, password)
 * are exposed; the browser suite keeps its own copy with the extra
 * group/department fields its policy tests need.
 *
 * Data source of truth: internal/acceptance/keycloak/pomerium-e2e-users-0.json
 */

import fs from "fs";
import path from "path";

export interface TestUser {
  /** Username — the key under which the user is exposed in testUsers. */
  username: string;
  /** Full email address, used as the Keycloak login identity. */
  email: string;
  /** Plaintext login password. */
  password: string;
}

interface RawTestUser {
  username: string;
  email: string;
}

/**
 * Load the realm's users and stamp the shared plaintext password. Passwords are
 * stored encrypted in the realm export and are currently all the same, so they
 * are added here rather than read from the JSON.
 */
function loadUsers(): TestUser[] {
  const fixturePath = path.resolve(__dirname, "../../keycloak/pomerium-e2e-users-0.json");
  const raw: { users: RawTestUser[] } = JSON.parse(fs.readFileSync(fixturePath, "utf-8"));
  if (!Array.isArray(raw.users)) {
    throw new Error("Invalid users fixture: 'users' must be an array.");
  }
  return raw.users.map((user) => ({
    username: user.username,
    email: user.email,
    password: "password123",
  }));
}

/** Test users available in the acceptance environment, keyed by username. */
export const testUsers: Record<string, TestUser> = Object.fromEntries(
  loadUsers().map((user) => [user.username, user]),
);
