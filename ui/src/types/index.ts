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
type RuntimeFlags = {
  runtimeFlags?: {
    routes_portal?: boolean;
    is_hosted_data_plane?: boolean;
  };
};

type BasePageData = {
  primaryColor?: string;
  secondaryColor?: string;
  logoUrl?: string;
  faviconUrl?: string;
};

export type ErrorPageData = BasePageData &
  RuntimeFlags & {
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

export type SidebarData = RuntimeFlags & {
  isEnterprise?: boolean;
  page?: string;
};

export type UserInfoData = RuntimeFlags & {
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

export type SignOutConfirmPageData = BasePageData &
  RuntimeFlags & {
    page: "SignOutConfirm";
    url: string;
  };

export type SignedOutPageData = BasePageData &
  RuntimeFlags & {
    page: "SignedOut";
  };

export type UserInfoPageData = BasePageData &
  UserInfoData & {
    page: "UserInfo";
  };

export type WebAuthnRegistrationPageData = BasePageData &
  RuntimeFlags & {
    page: "WebAuthnRegistration";

    creationOptions?: WebAuthnCreationOptions;
    requestOptions?: WebAuthnRequestOptions;
    selfUrl: string;
  };

export type SignInVerifyPageData = BasePageData &
  UserInfoData & {
    page: "SignInVerify";

    redirectUrl: string;
    issuedAt: Date;
    expiresAt: Date;
    sourceAddr: string;
    protocol: string;
  };

export type SignInSuccessPageData = BasePageData &
  UserInfoData & {
    page: "SignInSuccess";
    expiresAt: string;
    protocol: string;
  };

export type SessionBindingInfoPageData = BasePageData &
  UserInfoData & {
    page: "SessionBindingInfo";
    sessionBindings: SessionBindingData[];
  };
export type SessionBindingData = {
  SessionBindingID: string;
  Protocol: string;
  IssuedAt: string;
  ExpiresAt: string;
  RevokeSessionBindingURL: string;
  HasIdentityBinding: boolean;
  RevokeIdentityBindingURL: string;
  DetailsSSH: DetailsSSH;
};

export type DetailsSSH = {
  FingerprintID: string;
  SourceAddress: string;
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
  | SignInSuccessPageData
  | SessionBindingInfoPageData;

export type PolicyEvaluationTrace = {
  id?: string;
  explanation?: string;
  remediation?: string;
  allow?: boolean;
  deny?: boolean;
};
