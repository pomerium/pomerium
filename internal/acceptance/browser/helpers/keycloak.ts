/**
 * Keycloak Admin API helpers for E2E acceptance tests.
 * Provides functions to manage users and groups during test execution.
 */

import { urls, keycloakPaths } from "../fixtures/test-data.js";
import { getRunId } from "../fixtures/users.js";

/**
 * Keycloak admin client for test operations.
 */
export class KeycloakAdmin {
  private baseUrl: string;
  private realm: string;
  private adminUser: string;
  private adminPassword: string;
  private accessToken: string | null = null;

  constructor(options?: {
    baseUrl?: string;
    realm?: string;
    adminUser?: string;
    adminPassword?: string;
  }) {
    this.baseUrl = options?.baseUrl || urls.keycloak;
    this.realm = options?.realm || "pomerium-e2e";
    this.adminUser = options?.adminUser || process.env.KEYCLOAK_ADMIN || "admin";
    this.adminPassword =
      options?.adminPassword || process.env.KEYCLOAK_ADMIN_PASSWORD || "admin";
  }

  /**
   * Authenticate with Keycloak admin API.
   */
  async authenticate(): Promise<void> {
    const tokenUrl = `${this.baseUrl}/realms/master/protocol/openid-connect/token`;

    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        username: this.adminUser,
        password: this.adminPassword,
        grant_type: "password",
        client_id: "admin-cli",
      }),
    });

    if (!response.ok) {
      throw new Error(
        `Failed to authenticate with Keycloak admin API: ${response.status}`
      );
    }

    const data = await response.json();
    this.accessToken = data.access_token;
  }

  /**
   * Ensure we have a valid access token.
   */
  private async ensureAuthenticated(): Promise<string> {
    if (!this.accessToken) {
      await this.authenticate();
    }
    return this.accessToken!;
  }

  /**
   * Make an authenticated request to the admin API.
   */
  private async adminRequest(
    path: string,
    options?: RequestInit
  ): Promise<Response> {
    const token = await this.ensureAuthenticated();
    const url = `${this.baseUrl}/admin/realms/${this.realm}${path}`;

    return fetch(url, {
      ...options,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        ...options?.headers,
      },
    });
  }

  /**
   * Get user by username.
   */
  async getUserByUsername(username: string): Promise<KeycloakUser | null> {
    const response = await this.adminRequest(`/users?username=${username}&exact=true`);

    if (!response.ok) {
      throw new Error(`Failed to get user: ${response.status}`);
    }

    const users: KeycloakUser[] = await response.json();
    return users.length > 0 ? users[0] : null;
  }

  /**
   * Get user by email.
   */
  async getUserByEmail(email: string): Promise<KeycloakUser | null> {
    const response = await this.adminRequest(`/users?email=${email}&exact=true`);

    if (!response.ok) {
      throw new Error(`Failed to get user by email: ${response.status}`);
    }

    const users: KeycloakUser[] = await response.json();
    return users.length > 0 ? users[0] : null;
  }

  /**
   * Get group by name.
   */
  async getGroupByName(name: string): Promise<KeycloakGroup | null> {
    const response = await this.adminRequest(`/groups?search=${name}`);

    if (!response.ok) {
      throw new Error(`Failed to get group: ${response.status}`);
    }

    const groups: KeycloakGroup[] = await response.json();
    return groups.find((g) => g.name === name) || null;
  }

  /**
   * Add user to a group.
   */
  async addUserToGroup(userId: string, groupId: string): Promise<void> {
    const response = await this.adminRequest(`/users/${userId}/groups/${groupId}`, {
      method: "PUT",
    });

    if (!response.ok) {
      throw new Error(`Failed to add user to group: ${response.status}`);
    }
  }

  /**
   * Remove user from a group.
   */
  async removeUserFromGroup(userId: string, groupId: string): Promise<void> {
    const response = await this.adminRequest(`/users/${userId}/groups/${groupId}`, {
      method: "DELETE",
    });

    if (!response.ok) {
      throw new Error(`Failed to remove user from group: ${response.status}`);
    }
  }

  /**
   * Get user's groups.
   */
  async getUserGroups(userId: string): Promise<KeycloakGroup[]> {
    const response = await this.adminRequest(`/users/${userId}/groups`);

    if (!response.ok) {
      throw new Error(`Failed to get user groups: ${response.status}`);
    }

    return response.json();
  }

  /**
   * Remove a test user from a group by username (convenience method).
   * Username should be without the run prefix.
   */
  async removeTestUserFromGroup(username: string, groupName: string): Promise<void> {
    const prefixedUsername = `test-user-${getRunId()}-${username}`;

    const user = await this.getUserByUsername(prefixedUsername);
    if (!user) {
      throw new Error(`User not found: ${prefixedUsername}`);
    }

    const group = await this.getGroupByName(groupName);
    if (!group) {
      throw new Error(`Group not found: ${groupName}`);
    }

    await this.removeUserFromGroup(user.id, group.id);
  }

  /**
   * Add a test user to a group by username (convenience method).
   * Username should be without the run prefix.
   */
  async addTestUserToGroup(username: string, groupName: string): Promise<void> {
    const prefixedUsername = `test-user-${getRunId()}-${username}`;

    const user = await this.getUserByUsername(prefixedUsername);
    if (!user) {
      throw new Error(`User not found: ${prefixedUsername}`);
    }

    const group = await this.getGroupByName(groupName);
    if (!group) {
      throw new Error(`Group not found: ${groupName}`);
    }

    await this.addUserToGroup(user.id, group.id);
  }

  /**
   * Update user attributes.
   */
  async updateUserAttributes(
    userId: string,
    attributes: Record<string, string[]>
  ): Promise<void> {
    const response = await this.adminRequest(`/users/${userId}`, {
      method: "PUT",
      body: JSON.stringify({ attributes }),
    });

    if (!response.ok) {
      throw new Error(`Failed to update user attributes: ${response.status}`);
    }
  }

  /**
   * Logout all sessions for a user.
   */
  async logoutUser(userId: string): Promise<void> {
    const response = await this.adminRequest(`/users/${userId}/logout`, {
      method: "POST",
    });

    if (!response.ok && response.status !== 204) {
      throw new Error(`Failed to logout user: ${response.status}`);
    }
  }
}

/**
 * Keycloak user representation.
 */
export interface KeycloakUser {
  id: string;
  username: string;
  email?: string;
  emailVerified?: boolean;
  enabled?: boolean;
  firstName?: string;
  lastName?: string;
  attributes?: Record<string, string[]>;
}

/**
 * Keycloak group representation.
 */
export interface KeycloakGroup {
  id: string;
  name: string;
  path: string;
  subGroups?: KeycloakGroup[];
}

/**
 * Create a new Keycloak admin client instance.
 */
export function createKeycloakAdmin(): KeycloakAdmin {
  return new KeycloakAdmin();
}
