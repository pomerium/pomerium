export type Claims = Record<string, unknown[]>;

export type Session = {
  audience: string[];
  claims: Claims;
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
};

export type UserInfoData = {
  session?: Session;
  user?: User;
};
