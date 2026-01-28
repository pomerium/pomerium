/**
 * Test user definitions for E2E acceptance tests.
 * These users are created by the seed-keycloak.sh script.
 *
 * Source of truth: internal/acceptance/fixtures/users.json
 */

import fs from "fs";
import path from "path";

export interface TestUser {
  /** Username (without run prefix) */
  username: string;
  /** Full email address */
  email: string;
  /** Password for login */
  password: string;
  /** Groups the user belongs to */
  groups: string[];
  /** Department attribute */
  department: string;
  /** Email domain (extracted from email) */
  emailDomain: string;
}

interface RawTestUser {
  username: string;
  email: string;
  password: string;
  groups: string[];
  department: string;
}

interface UsersFixture {
  users: RawTestUser[];
}

/**
 * Get the run ID from environment or use default.
 */
export function getRunId(): string {
  return process.env.RUN_ID || "default";
}

/**
 * Get the prefixed username for a test user.
 */
export function getPrefixedUsername(username: string): string {
  return `test-user-${getRunId()}-${username}`;
}

/**
 * Test users available in the acceptance test environment.
 * The actual usernames in Keycloak are prefixed with `test-user-{RUN_ID}-`.
 */
function loadUsersFixture(): UsersFixture {
  const fixturePath = path.resolve(__dirname, "../../fixtures/users.json");
  const raw = fs.readFileSync(fixturePath, "utf-8");
  return JSON.parse(raw) as UsersFixture;
}

function toTestUser(raw: RawTestUser): TestUser {
  const emailDomain = raw.email.split("@")[1] || "";
  return {
    ...raw,
    emailDomain,
  };
}

const usersFixture = loadUsersFixture();
if (!Array.isArray(usersFixture.users)) {
  throw new Error("Invalid users fixture: 'users' must be an array.");
}

export const testUsers: Record<string, TestUser> = Object.fromEntries(
  usersFixture.users.map((user) => [user.username, toTestUser(user)])
);

/**
 * Get a test user by name.
 */
export function getUser(name: keyof typeof testUsers): TestUser {
  const user = testUsers[name];
  if (!user) {
    throw new Error(`Unknown test user: ${name}`);
  }
  return user;
}

/**
 * Get the Keycloak username for a test user (with run prefix).
 */
export function getKeycloakUsername(user: TestUser): string {
  return getPrefixedUsername(user.username);
}
