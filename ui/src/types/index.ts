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

export type WebAuthnCreationOptions = {
  attestation: AttestationConveyancePreference;
  authenticatorSelection: {
    authenticatorAttachment?: AuthenticatorAttachment;
    requireResidentKey?: boolean;
    residentKey?: ResidentKeyRequirement;
    userVerification?: UserVerificationRequirement;
  };
  challenge: string;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  rp: {
    name: string;
  };
  timeout: number;
  user: {
    displayName: string;
    id: string;
    name: string;
  };
};

export type WebAuthnRequestOptions = {
  allowCredentials: Array<{
    type: "public-key";
    id: string;
  }>;
  challenge: string;
  timeout: number;
  userVerification: UserVerificationRequirement;
};

// page data

type BasePageData = {
  csrfToken?: string;
  primaryColor?: string;
  secondaryColor?: string;
  logoUrl?: string;
  faviconUrl?: string;
};

export type ErrorPageData = BasePageData & {
  page: "Error";

  canDebug?: boolean;
  debugUrl?: string;
  requestId?: string;
  status?: number;
  statusText?: string;
  errorMessageFirstParagraph?: string;
  policyEvaluationTraces?: PolicyEvaluationTrace[];
};

export type UserInfoData = {
  csrfToken: string;
  directoryGroups?: Group[];
  directoryUser?: DirectoryUser;
  session?: Session;
  user?: User;
  webAuthnCreationOptions?: WebAuthnCreationOptions;
  webAuthnRequestOptions?: WebAuthnRequestOptions;
  webAuthnUrl?: string;
};

export type DeviceEnrolledPageData = BasePageData &
  UserInfoData & {
    page: "DeviceEnrolled";
  };

export type SignOutConfirmPageData = BasePageData & {
  page: "SignOutConfirm";
  url: string;
};

export type UserInfoPageData = BasePageData &
  UserInfoData & {
    page: "UserInfo";
  };

export type WebAuthnRegistrationPageData = BasePageData & {
  page: "WebAuthnRegistration";

  creationOptions?: WebAuthnCreationOptions;
  csrfToken: string;
  requestOptions?: WebAuthnRequestOptions;
  selfUrl: string;
};

export type PageData =
  | ErrorPageData
  | DeviceEnrolledPageData
  | SignOutConfirmPageData
  | UserInfoPageData
  | WebAuthnRegistrationPageData;

export type PolicyEvaluationTrace = {
  id?: string;
  explanation?: string;
  remediation?: string;
  allow?: boolean;
  deny?: boolean;
};
