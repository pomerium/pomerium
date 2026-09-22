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
    mcp?: boolean;
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

export type SidebarData = RuntimeFlags;

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
  type: "http" | "tcp" | "udp" | "mcp";
  from: string;
  connect_command?: string;
  description: string;
  logo_url: string;
  mcp_connect_url?: string;
  mcp_connected?: boolean;
  // mcp_needs_oauth is false for a listed MCP server that has no upstream to
  // connect to, so the card shows no connection state at all. Undefined means
  // "yes" (the routes portal only ever lists connectable MCP routes).
  mcp_needs_oauth?: boolean;
};

export type RoutesPageData = BasePageData &
  UserInfoData & {
    page: "Routes";
    routes: Route[];
    mcp_status_error?: string;
  };

export type AgenticLabel = {
  key: string;
  value: string;
};

export type AgenticExecutorClaim = {
  path: string;
  value: string;
};

export type AgenticApprovePageData = BasePageData &
  RuntimeFlags & {
    page: "AgenticApprove";

    userEmail: string;
    userId: string;
    prompt: string;
    labels: AgenticLabel[];
    mcpServers: Route[];
    approvePath: string;
    needsConnect: boolean;
    connectError: string;
    executor: AgenticExecutorClaim[];
    code: string;
    // sessionsUrl is the approver's client-bindings page, where this run lands
    // after approval and can be revoked. Empty if the deployment has no usable
    // authenticate URL.
    sessionsUrl: string;
  };

export type AgenticApproveResultPageData = BasePageData &
  RuntimeFlags & {
    page: "AgenticApproveResult";

    severity: "success" | "info" | "warning";
    title: string;
    message: string;
  };

export type SignOutConfirmPageData = BasePageData &
  RuntimeFlags & {
    page: "SignOutConfirm";
    url: string;
    reauth_enabled: boolean;
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
    reauth_enabled: boolean;
    // highlight is the SessionBindingID of one row to call out, e.g. the run
    // the user has just approved. An id matching no row highlights nothing.
    highlight?: string;
  };
export type SessionBindingData = {
  SessionBindingID: string;
  Protocol: string;
  Resource: string;
  ClientAddress: string;
  InitiatedAt: string;
  ExpiresAt: string;
  RevokeSessionBindingURL: string;
  HasIdentityBinding: boolean;
  RevokeIdentityBindingURL: string;
  DetailsSSH?: DetailsSSH;
  IsCurrentBrowser: boolean;
  DetailsAgentic?: DetailsAgentic;
};

export type DetailsSSH = {
  FingerprintID: string;
  SourceAddress: string;
};

export type DetailsAgentic = {
  RunID: string;
  Labels?: Record<string, string>;
  Prompt: string;
  WorkloadClaims?: Record<string, string>;
};

export type PageData =
  | AgenticApprovePageData
  | AgenticApproveResultPageData
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
