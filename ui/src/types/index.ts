export type Claims = Record<string, unknown[]>;

export type DirectoryUser = {
  displayName: string;
  email: string;
  groupIds: string[];
  id: string;
};

export type Group = {
  id: string;
  email: string;
  name: string;
};

export type Session = {
  audience: string[];
  claims: Claims;
  deviceCredentials: Array<{
    typeId: string;
    id: string;
  }>;
  expiresAt: string;
  id: string;
  idToken: {
    expiresAt: string;
    issuedAt: string;
    issuer: string;
    raw: string;
    subject: string;
  };
  issuedAt: string;
  oauthToken: {
    accessToken: string;
    expiresAt: string;
    refreshToken: string;
    tokenType: string;
  };
  userId: string;
};

export type User = {
  claims: Claims;
  deviceCredentialIds: string[];
  id: string;
  name: string;
};

export type UserInfoData = {
  csrfToken: string;
  directoryGroups?: Group[];
  directoryUser?: DirectoryUser;
  session?: Session;
  signOutUrl?: string;
  user?: User;
  webAuthnUrl?: string;
};
