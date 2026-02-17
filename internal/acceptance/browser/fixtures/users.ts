/**
 * Test user definitions for E2E acceptance tests.
 *
 * Source of truth: internal/acceptance/keycloak/pomerium-e2e-users-0.json
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
  attributes: { department: string[] };
}

interface UsersFixture {
  users: RawTestUser[];
}

/**
 * Test users available in the acceptance test environment.
 */
function loadUsersFixture(): UsersFixture {
  const fixturePath = path.resolve(__dirname, "../../keycloak/pomerium-e2e-users-0.json");
  const raw = fs.readFileSync(fixturePath, "utf-8");
  // Passwords are stored encrypted in the keycloak realm data, so we need
  // to add the plaintext password separately. Currently all of the passwords
  // are the same.
  const users = JSON.parse(raw).users.map((user: Object) => ({
    ...user,
    password: 'password123',
  }));
  return { users };
}

function toTestUser(raw: RawTestUser): TestUser {
  const emailDomain = raw.email.split("@")[1] || "";
  return {
    ...raw,
    emailDomain,
    department: raw.attributes.department[0],
  };
}

const usersFixture = loadUsersFixture();
if (!Array.isArray(usersFixture.users)) {
  throw new Error("Invalid users fixture: 'users' must be an array.");
}

export const testUsers: Record<string, TestUser> = Object.fromEntries(
  usersFixture.users.map((user) => [user.username, toTestUser(user)])
);
