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

export type Profile = {
  claims: Record<string, unknown>;
};

export type Session = {
  claims: Claims;
  deviceCredentials: Array<{
    typeId: string;
    id: string;
  }>;
  expiresAt: string;
  id: string;
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
    id: string;
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
  rpId: string;
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
  page: "Error" | "UpstreamError";

  canDebug?: boolean;
  debugUrl?: string;
  requestId?: string;
  status?: number;
  statusText?: string;
  description?: string;
  errorMessageFirstParagraph?: string;
  policyEvaluationTraces?: PolicyEvaluationTrace[];
};

export type UserInfoData = {
  csrfToken: string;
  directoryGroups?: Group[];
  directoryUser?: DirectoryUser;
  isEnterprise?: boolean;
  session?: Session;
  user?: User;
  profile?: Profile;
  webAuthnCreationOptions?: WebAuthnCreationOptions;
  webAuthnRequestOptions?: WebAuthnRequestOptions;
  webAuthnUrl?: string;
};

export type DeviceEnrolledPageData = BasePageData &
  UserInfoData & {
    page: "DeviceEnrolled";
  };

export type Route = {
  id: string;
  name: string;
  type: "http" | "tcp" | "udp";
  from: string;
  connect_command?: string;
  description: string;
  logo_url: string;
};

export type RoutesPageData = BasePageData &
  UserInfoData & {
    page: "Routes";
    routes: Route[];
  };

export type SignOutConfirmPageData = BasePageData & {
  page: "SignOutConfirm";
  url: string;
};

export type SignedOutPageData = BasePageData & {
  page: "SignedOut";
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

export type SignInVerifyPageData = BasePageData & {
  page: "SignInVerify";

  redirectUrl: string
  // TODO
};

export type SignInSuccessPageData = BasePageData & {
  page: "SignInSuccess";

  // TODO
};

export type PageData =
  | ErrorPageData
  | DeviceEnrolledPageData
  | RoutesPageData
  | SignOutConfirmPageData
  | SignedOutPageData
  | UserInfoPageData
  | WebAuthnRegistrationPageData
  | SignInVerifyPageData
  | SignInSuccessPageData;

export type PolicyEvaluationTrace = {
  id?: string;
  explanation?: string;
  remediation?: string;
  allow?: boolean;
  deny?: boolean;
};
