# MCP Proxying Architecture

This document describes how Pomerium proxies MCP (Model Context Protocol) traffic,
injecting upstream OAuth tokens and intercepting auth challenges transparently.

## Table of Contents

- [Overview](#overview)
- [Dual-Role OAuth Architecture](#dual-role-oauth-architecture)
- [Envoy Filter Chain](#envoy-filter-chain)
- [Metadata Pipeline: ext\_authz to ext\_proc](#metadata-pipeline-ext_authz-to-ext_proc)
- [Request Path: Token Injection](#request-path-token-injection)
- [Response Path: 401/403 Interception](#response-path-401403-interception)
- [Upstream OAuth Discovery](#upstream-oauth-discovery)
- [Client Registration (DCR and CIMD)](#client-registration-dcr-and-cimd)
- [The Callback Flow](#the-callback-flow)
- [Downstream vs Upstream Host Routing](#downstream-vs-upstream-host-routing)
- [Storage Model](#storage-model)
- [Configuration and Wiring](#configuration-and-wiring)
- [Endpoint Map](#endpoint-map)
- [Key Files](#key-files)

---

## Overview

Pomerium acts as an MCP-aware reverse proxy. An MCP client (e.g., Claude Desktop)
connects to Pomerium, which authenticates the client using its own OAuth 2.1
Authorization Server, then proxies requests to an upstream MCP server (e.g.,
GitHub's MCP API, Linear's MCP API). The upstream server may itself require OAuth
tokens that Pomerium must obtain on the user's behalf.

Two Envoy filters work in tandem to make this work:

1. **ext_authz** — Pomerium's existing authorization filter. Authenticates the
   user, evaluates policy, and passes route metadata downstream.
2. **ext_proc** — A new external processor filter. Intercepts request/response
   headers on MCP routes to inject upstream tokens and handle auth challenges.

```mermaid
flowchart LR
    Client["MCP Client<br/>(e.g. Claude)"]
    Envoy["Envoy Proxy"]
    ExtAuthz["ext_authz<br/>(Pomerium Authorize)"]
    ExtProc["ext_proc<br/>(Pomerium Control Plane)"]
    Upstream["Upstream MCP Server<br/>(e.g. GitHub, Linear)"]

    Client -->|"HTTPS"| Envoy
    Envoy -->|"gRPC"| ExtAuthz
    Envoy -->|"gRPC"| ExtProc
    Envoy -->|"HTTPS"| Upstream

    style ExtAuthz fill:#e1f5fe
    style ExtProc fill:#fff3e0
```

---

## Dual-Role OAuth Architecture

Pomerium participates in two separate OAuth 2.1 flows simultaneously:

```mermaid
flowchart TB
    subgraph Downstream["Downstream OAuth (Pomerium as AS)"]
        MCPClient["MCP Client"]
        PomAS["Pomerium AS<br/><code>/.well-known/oauth-authorization-server</code><br/><code>/.pomerium/mcp/authorize</code><br/><code>/.pomerium/mcp/token</code>"]
        MCPClient -->|"1. Discover PRM"| PomAS
        MCPClient -->|"2. Authorization Code + PKCE"| PomAS
        MCPClient -->|"3. Token Exchange"| PomAS
    end

    subgraph Upstream["Upstream OAuth (Pomerium as Client)"]
        PomClient["Pomerium<br/>(OAuth Client)"]
        UpstreamAS["Upstream AS<br/>(e.g. GitHub OAuth)"]
        UpstreamRS["Upstream MCP Server<br/>(Resource Server)"]
        PomClient -->|"1. PRM Discovery"| UpstreamRS
        PomClient -->|"2. AS Metadata"| UpstreamAS
        PomClient -->|"3. DCR / CIMD"| UpstreamAS
        PomClient -->|"4. Authorization Code + PKCE"| UpstreamAS
        PomClient -->|"5. Token Exchange"| UpstreamAS
    end

    PomAS -.->|"links pending state<br/>to complete both flows"| PomClient

    style Downstream fill:#e8f5e9
    style Upstream fill:#fce4ec
```

**Downstream flow**: The MCP client authenticates with Pomerium's own OAuth AS.
Pomerium serves its own Protected Resource Metadata (PRM), Authorization Server
metadata, and standard OAuth endpoints (`/authorize`, `/token`, `/register`).

**Upstream flow**: Pomerium acts as an OAuth client to the upstream MCP server's
authorization server. This flow is triggered when the upstream returns a 401/403,
intercepted by ext_proc.

The key link between the two flows is the **PendingUpstreamAuth** state. When
ext_proc intercepts a 401 from upstream, it stores pending auth state and returns
a 401 to the MCP client with Pomerium's own PRM URL. The MCP client then
re-runs its auth flow against Pomerium, which links the Pomerium authorization
request to the pending upstream auth state and redirects the user to the upstream
AS for consent.

---

## Envoy Filter Chain

The main HTTP connection manager filter chain is ordered as follows:

```mermaid
flowchart TD
    A["1. Lua: RemoveImpersonateHeaders"]
    B["2. Lua: SetClientCertificateMetadata"]
    C["3. ext_authz<br/>(Pomerium Authorize gRPC)"]
    D["4. ext_proc<br/>(Pomerium Control Plane gRPC)<br/><b>Disabled by default</b>"]
    E["5. Lua: ExtAuthzSetCookie"]
    F["6. Lua: CleanUpstream"]
    G["7. Lua: RewriteHeaders"]
    H["8. Lua: LocalReplyType"]
    I["9. SetConnectionState"]
    J["10. Router"]

    A --> B --> C --> D --> E --> F --> G --> H --> I --> J

    style C fill:#e1f5fe
    style D fill:#fff3e0
```

**ext_proc is globally disabled** (`Disabled: true` in the HttpFilter config).
It only activates on routes where per-route config overrides enable it —
specifically, routes with `policy.IsMCPServer() == true`.

Both ext_authz and ext_proc connect to Pomerium's gRPC server(s):
- ext_authz → `pomerium-authorize` cluster (the Authorize service)
- ext_proc → `pomerium-control-plane-grpc` cluster (the Control Plane service)

### Per-Route Activation

When building Envoy route config, MCP server routes get a per-route override
that enables ext_proc:

```
config/envoyconfig/routes.go:
  if policy.IsMCPServer() {
      route.TypedPerFilterConfig["envoy.filters.http.ext_proc"] = PerFilterConfigExtProcEnabled()
  }
```

The override sets processing mode to `SEND` for request and response headers,
and `NONE`/`SKIP` for bodies and trailers:

| Phase | Mode | Reason |
|---|---|---|
| Request Headers | `SEND` | Inject Authorization header |
| Request Body | `NONE` | No body inspection needed |
| Response Headers | `SEND` | Intercept 401/403 status |
| Response Body | `NONE` | No body inspection needed |
| Trailers | `SKIP` | Not relevant |

### Metadata Forwarding

The ext_proc filter is configured with `MetadataOptions.ForwardingNamespaces`
to receive ext_authz's DynamicMetadata:

```
ForwardingNamespaces.Untyped: ["envoy.filters.http.ext_authz"]
```

This is how route context (session ID, route ID, upstream host) flows from
ext_authz to ext_proc. Without this, ext_proc would have no knowledge of the
authenticated user or the route configuration.

---

## Metadata Pipeline: ext_authz to ext_proc

The metadata pipeline is the critical data handoff between Pomerium's
authorization service and the ext_proc token injection logic.

```mermaid
sequenceDiagram
    participant Client
    participant Envoy
    participant ExtAuthz as ext_authz<br/>(Authorize)
    participant ExtProc as ext_proc<br/>(Control Plane)
    participant Upstream

    Client->>Envoy: HTTP Request
    Envoy->>ExtAuthz: CheckRequest
    ExtAuthz->>ExtAuthz: Evaluate policy
    ExtAuthz->>Envoy: CheckResponse (OK)<br/>+ DynamicMetadata
    Note over ExtAuthz,Envoy: DynamicMetadata contains:<br/>route_id, session_id,<br/>is_mcp, upstream_host

    Envoy->>ExtProc: ProcessingRequest (RequestHeaders)<br/>+ MetadataContext (forwarded)
    ExtProc->>ExtProc: extractRouteContext()
    ExtProc->>Envoy: ProcessingResponse

    Envoy->>Upstream: Proxied Request
```

### Metadata Structure

The metadata is nested under two namespaces:

```
MetadataContext.FilterMetadata
  └── "envoy.filters.http.ext_authz"          (ExtAuthzMetadataNamespace)
        └── "com.pomerium.route-context"       (RouteContextMetadataNamespace)
              ├── "route_id"      string        Envoy route ID
              ├── "session_id"    string        Pomerium session ID
              ├── "is_mcp"        bool          Always true for MCP routes
              └── "upstream_host" string        Actual upstream hostname (e.g. "api.github.com")
```

**Producer** (`authorize/route_context_metadata.go`):
`BuildRouteContextMetadata()` creates this struct when ext_authz approves a
request for an MCP server route. The upstream host comes from
`request.Policy.To[0].URL.Hostname()`.

**Consumer** (`internal/mcp/extproc/server.go`):
`extractRouteContext()` walks the metadata path to build a `RouteContext` struct.

---

## Request Path: Token Injection

When ext_proc receives request headers for an MCP route, it attempts to inject
a cached upstream token.

```mermaid
flowchart TD
    Start["RequestHeaders received"]
    CheckMCP{"routeCtx != nil<br/>AND routeCtx.IsMCP?"}
    CheckHandler{"handler != nil?"}
    GetToken["handler.GetUpstreamToken(<br/>ctx, routeCtx, downstreamHost)"]
    CheckError{"Error?"}
    CheckToken{"Token non-empty?"}
    Inject["Inject Authorization: Bearer &lt;token&gt;"]
    Continue["CONTINUE (no token)"]
    BadGateway["502 Bad Gateway"]
    PassThrough["CONTINUE (pass through)"]

    Start --> CheckMCP
    CheckMCP -->|No| PassThrough
    CheckMCP -->|Yes| CheckHandler
    CheckHandler -->|No| PassThrough
    CheckHandler -->|Yes| GetToken
    GetToken --> CheckError
    CheckError -->|Yes| BadGateway
    CheckError -->|No| CheckToken
    CheckToken -->|Yes| Inject
    CheckToken -->|No| Continue
```

### Token Lookup Dispatch

`GetUpstreamToken` dispatches based on route configuration:

```mermaid
flowchart TD
    Start["GetUpstreamToken(host)"]
    StripPort["hostname = stripPort(host)"]
    CheckStatic{"GetOAuth2ConfigForHost(hostname)?"}
    CheckAuto{"UsesAutoDiscovery(hostname)?"}
    StaticPath["getStaticUpstreamOAuth2Token()<br/>golang.org/x/oauth2 TokenSource"]
    AutoPath["getAutoDiscoveryToken()<br/>Look up UpstreamMCPToken in databroker"]
    NoToken["return empty string"]

    Start --> StripPort --> CheckStatic
    CheckStatic -->|Yes| StaticPath
    CheckStatic -->|No| CheckAuto
    CheckAuto -->|Yes| AutoPath
    CheckAuto -->|No| NoToken
```

**Static path** (`upstream_oauth2` config): Uses the standard Go `oauth2.Config.TokenSource`
which handles refresh automatically. Tokens are stored per `{host, user_id}`.

**Auto-discovery path** (no `upstream_oauth2` config): Looks up `UpstreamMCPToken`
by `{user_id, route_id, upstream_server}`. If expired with both a refresh token
and a stored token endpoint, performs inline refresh via singleflight. If
expired without a refresh token (or without a token endpoint), deletes the
stale token and returns empty (the subsequent 401 from upstream will trigger
the full OAuth flow).

---

## Response Path: 401/403 Interception

When upstream returns 401 or 403, ext_proc delegates to the handler which
may initiate the upstream OAuth flow.

```mermaid
flowchart TD
    Start["ResponseHeaders received"]
    ParseStatus["Parse :status pseudo-header"]
    Check401{"status == 401<br/>or status == 403?"}
    GetWWWAuth["Extract WWW-Authenticate header"]
    CallHandler["handler.HandleUpstreamResponse(<br/>ctx, routeCtx, downstreamHost,<br/>originalURL, status, wwwAuth)"]
    CheckError{"Error?"}
    CheckAction{"action != nil AND<br/>action.WWWAuthenticate != ''?"}
    Return401["Immediate 401 Response<br/>WWW-Authenticate: Bearer resource_metadata=&quot;...&quot;"]
    PassThrough["CONTINUE (pass through upstream response)"]
    BadGateway["502 Bad Gateway"]
    ContinueNon401["CONTINUE"]

    Start --> ParseStatus --> Check401
    Check401 -->|No| ContinueNon401
    Check401 -->|Yes| GetWWWAuth --> CallHandler
    CallHandler --> CheckError
    CheckError -->|Yes| BadGateway
    CheckError -->|No| CheckAction
    CheckAction -->|Yes| Return401
    CheckAction -->|No| PassThrough
```

### HandleUpstreamResponse Decision Tree

```mermaid
flowchart TD
    Start["HandleUpstreamResponse(host, originalURL, status, wwwAuth)"]
    StripPort2["hostname = stripPort(host)"]
    CheckAuto{"UsesAutoDiscovery(hostname)?"}
    PassThrough["return nil (pass through)"]
    ParseWWW["Parse WWW-Authenticate"]
    Check401{"status == 401?"}
    Check403{"status == 403 AND<br/>wwwAuth != nil AND<br/>error == 'insufficient_scope'?"}
    Handle401["handle401():<br/>1. getServerInfo(hostname)<br/>2. stripQueryFromURL(originalURL) → resourceURL<br/>3. getUserID(ctx, sessionID)<br/>4. runUpstreamOAuthSetup():<br/>&nbsp;&nbsp;- PRM + AS discovery<br/>&nbsp;&nbsp;- Determine client_id (DCR/CIMD)<br/>5. Generate PKCE<br/>6. Generate state<br/>7. Store PendingUpstreamAuth<br/>8. Return 401 with Pomerium PRM URL"]

    Start --> StripPort2 --> CheckAuto
    CheckAuto -->|No| PassThrough
    CheckAuto -->|Yes| ParseWWW --> Check401
    Check401 -->|Yes| Handle401
    Check401 -->|No| Check403
    Check403 -->|Yes| Handle401
    Check403 -->|No| PassThrough
```

---

## Upstream OAuth Discovery

When the upstream returns a 401, Pomerium must discover the upstream's OAuth
configuration. This follows the MCP authorization spec (Protocol Revision 2025-11-25)
and RFC 9728 (Protected Resource Metadata).

```mermaid
flowchart TD
    Start["runDiscovery(ctx, httpClient, wwwAuth, upstreamServerURL, overrideASURL)"]

    subgraph PRM["Step 1: Protected Resource Metadata (RFC 9728)"]
        CheckHint{"WWW-Authenticate has<br/>resource_metadata?"}
        FetchHint["Fetch PRM from hint URL"]
        BuildURLs["Build well-known PRM URLs:<br/>1. {origin}/.well-known/oauth-protected-resource/{path}<br/>2. {origin}/.well-known/oauth-protected-resource"]
        TryURLs["Try each URL"]
    end

    subgraph ASVIA["Step 2a: AS via PRM"]
        ValidatePRM["Validate PRM.resource matches upstream URL"]
        GetIssuer["AS issuer = PRM.authorization_servers[0]"]
        FetchASM["Fetch AS Metadata (RFC 8414):<br/>1. {origin}/.well-known/oauth-authorization-server[/{path}]<br/>2. {origin}/.well-known/openid-configuration[/{path}]<br/>3. {origin}[/{path}]/.well-known/openid-configuration"]
        ValidateASM["Validate AS:<br/>- S256 in code_challenge_methods<br/>- authorization_code in grant_types (if field present;<br/>&nbsp;&nbsp;omitted = implied per RFC 8414 §2)"]
    end

    subgraph Fallback["Step 2b: Direct AS Fallback"]
        CheckOverride{"overrideASURL<br/>configured?"}
        UseOverride["Use overrideASURL"]
        UseOrigin["Use origin of upstreamURL"]
        FetchFallbackASM["Fetch AS Metadata"]
    end

    Start --> CheckHint
    CheckHint -->|Yes| FetchHint
    CheckHint -->|No| BuildURLs --> TryURLs

    FetchHint -->|Success| ValidatePRM
    TryURLs -->|Success| ValidatePRM
    ValidatePRM --> GetIssuer --> FetchASM --> ValidateASM

    FetchHint -->|Failure| CheckOverride
    TryURLs -->|All failed| CheckOverride
    CheckOverride -->|Yes| UseOverride --> FetchFallbackASM
    CheckOverride -->|No| UseOrigin --> FetchFallbackASM

    style PRM fill:#e8f5e9
    style ASVIA fill:#e1f5fe
    style Fallback fill:#fff8e1
```

---

## Client Registration (DCR and CIMD)

After discovering the upstream AS metadata, Pomerium needs a `client_id` to use
in the authorization request. Two mechanisms are supported:

```mermaid
flowchart TD
    Start["Determine client_id"]
    CheckDCR{"AS has<br/>registration_endpoint?"}
    CheckCIMD{"AS supports<br/>client_id_metadata_document?"}
    Error["Error: no way to get client_id"]

    subgraph DCR["Dynamic Client Registration (RFC 7591)"]
        CheckCache{"Cached registration<br/>for issuer + host?"}
        UseCached["Use cached client_id"]
        Register["POST /register<br/>{client_name, redirect_uris,<br/>grant_types, response_types,<br/>token_endpoint_auth_method: none}"]
        CacheIt["Cache registration<br/>in databroker"]
    end

    subgraph CIMD["Client ID Metadata Document"]
        BuildURL["client_id = https://downstream_host<br/>/.pomerium/mcp/client/metadata.json"]
    end

    Start --> CheckDCR
    CheckDCR -->|Yes| CheckCache
    CheckCache -->|Yes| UseCached
    CheckCache -->|No| Register --> CacheIt
    CheckDCR -->|No| CheckCIMD
    CheckCIMD -->|Yes| BuildURL
    CheckCIMD -->|No| Error

    style DCR fill:#e8f5e9
    style CIMD fill:#e1f5fe
```

DCR is preferred because the Pomerium proxy's CIMD URL (on the downstream
domain) may not be reachable from the upstream AS (e.g., local dev domains).
DCR registrations are cached per `{issuer, downstream_host}` and shared across
all users.

---

## The Callback Flow

The complete end-to-end flow when an MCP client first accesses an upstream
MCP server that requires OAuth:

```mermaid
sequenceDiagram
    participant Client as MCP Client
    participant Envoy
    participant ExtProc as ext_proc
    participant PomHTTP as Pomerium HTTP<br/>(MCP Handler)
    participant UpstreamRS as Upstream MCP Server
    participant UpstreamAS as Upstream AS

    Note over Client,UpstreamAS: Phase 1: Initial request triggers 401 cascade

    Client->>Envoy: Request to MCP server
    Envoy->>ExtProc: RequestHeaders (no cached token)
    ExtProc->>Envoy: CONTINUE (no token to inject)
    Envoy->>UpstreamRS: Proxied request (no auth)
    UpstreamRS->>Envoy: 401 + WWW-Authenticate
    Envoy->>ExtProc: ResponseHeaders (401)
    ExtProc->>ExtProc: HandleUpstreamResponse():<br/>- PRM discovery<br/>- AS metadata<br/>- DCR/CIMD<br/>- Generate PKCE + state<br/>- Store PendingUpstreamAuth
    ExtProc->>Envoy: Immediate 401<br/>WWW-Authenticate: Bearer resource_metadata="https://downstream/.well-known/..."

    Note over Client,UpstreamAS: Phase 2: MCP client runs OAuth against Pomerium

    Client->>Envoy: Discover Pomerium PRM
    Envoy->>PomHTTP: GET /.well-known/oauth-protected-resource
    PomHTTP->>Client: Pomerium PRM (issuer, AS metadata URL)

    Client->>Envoy: Discover Pomerium AS metadata
    Envoy->>PomHTTP: GET /.well-known/oauth-authorization-server
    PomHTTP->>Client: Pomerium AS metadata (endpoints)

    Client->>Envoy: GET /.pomerium/mcp/authorize?...
    Envoy->>PomHTTP: Authorize request

    Note over PomHTTP: resolveAutoDiscoveryAuth()<br/>(defined in handler_connect.go,<br/>called from both Authorize and ConnectGet):<br/>1. Find PendingUpstreamAuth<br/>2. Link AuthReqID<br/>3. Build upstream auth URL

    PomHTTP->>Client: 302 Redirect to Upstream AS

    Note over Client,UpstreamAS: Phase 3: User authenticates with upstream

    Client->>UpstreamAS: Authorization request + PKCE
    UpstreamAS->>UpstreamAS: User consent
    UpstreamAS->>PomHTTP: Redirect callback?code=XXX&state=YYY

    Note over PomHTTP: ClientOAuthCallback():<br/>1. Look up PendingUpstreamAuth by state<br/>2. Exchange code for tokens (+ resource param)<br/>3. Store UpstreamMCPToken<br/>4. Delete PendingUpstreamAuth<br/>5. Complete Pomerium auth flow (issue auth code)

    PomHTTP->>Client: 302 Redirect with Pomerium auth code
    Client->>PomHTTP: POST /.pomerium/mcp/token (exchange code)
    PomHTTP->>Client: Pomerium access token

    Note over Client,UpstreamAS: Phase 4: Subsequent requests use cached token

    Client->>Envoy: Request to MCP server (with Pomerium token)
    Envoy->>ExtProc: RequestHeaders
    ExtProc->>ExtProc: GetUpstreamToken() → cached token found
    ExtProc->>Envoy: Inject Authorization: Bearer <upstream_token>
    Envoy->>UpstreamRS: Proxied request (with upstream auth)
    UpstreamRS->>Client: 200 OK
```

---

## Downstream vs Upstream Host Routing

This is the most subtle aspect of the architecture. Envoy rewrites the
`:authority` header to the upstream host **after** ext_proc processes request
headers, so ext_proc sees the downstream host in `:authority`.

```mermaid
flowchart LR
    subgraph "What ext_proc sees"
        DH[":authority = github.localhost.pomerium.io<br/>(downstream host)"]
        UH["routeCtx.UpstreamHost = api.github.com<br/>(from ext_authz metadata)"]
    end

    subgraph "What Envoy sends upstream"
        RH[":authority = api.github.com<br/>(rewritten by Router)"]
    end

    DH -->|"Used for"| Uses1["HostInfo lookups<br/>Callback URLs<br/>CIMD URLs<br/>PRM URL in 401 response"]
    UH -->|"Used for"| Uses2["originalURL construction<br/>PRM discovery<br/>Token storage keys<br/>OAuth resource parameter"]

    style DH fill:#e8f5e9
    style UH fill:#fce4ec
```

| Value | Source | Used For |
|---|---|---|
| `downstreamHost` | `:authority` pseudo-header | HostInfo lookups, callback/CIMD URL construction, PRM URL in 401 responses |
| `upstreamHost` | `routeCtx.UpstreamHost` from ext_authz metadata | `originalURL` construction, PRM discovery, token storage keys, OAuth `resource` parameter |

**Critical rule**: Never pass `upstreamHost` to HostInfo lookups (HostInfo is
keyed by downstream hostnames from `policy.GetFrom()`). Never use
`downstreamHost` for PRM discovery or the OAuth resource parameter (those
must use the actual upstream URL).

---

## Storage Model

All MCP-related state is stored in the **databroker**, Pomerium's distributed
key-value store. Records are protobuf messages serialized into `anypb.Any`.

```mermaid
erDiagram
    UpstreamMCPToken {
        string user_id PK
        string route_id PK
        string upstream_server PK
        string access_token
        string refresh_token
        string token_type
        timestamp issued_at
        timestamp expires_at
        timestamp refresh_expires_at
        string[] scopes
        string audience
        string authorization_server_issuer
        string token_endpoint
        string resource_param
    }

    PendingUpstreamAuth {
        string user_id PK
        string downstream_host PK
        string state_id UK
        string route_id
        string upstream_server
        string pkce_verifier
        string[] scopes
        string authorization_endpoint
        string token_endpoint
        string authorization_server_issuer
        string original_url
        string redirect_uri
        string client_id
        string client_secret
        timestamp created_at
        timestamp expires_at
        string auth_req_id
        string pkce_challenge
        string resource_param
    }

    UpstreamOAuthClient {
        string issuer PK
        string downstream_host PK
        string client_id
        string client_secret
        string redirect_uri
        string registration_endpoint
        timestamp created_at
    }

    TokenResponse {
        string host PK
        string user_id PK
        string access_token
        string refresh_token
        string token_type
        timestamp expires_at
    }

    Session {
        string id PK
        string user_id
    }

    UpstreamMCPToken }o--|| Session : "user_id via session"
    PendingUpstreamAuth }o--|| Session : "user_id via session"
    TokenResponse }o--|| Session : "user_id via session"
```

| Type | Composite Key | Purpose | Lifetime |
|---|---|---|---|
| `UpstreamMCPToken` | `{user_id, route_id, upstream_server}` | Cached upstream tokens (auto-discovery) | Until expiry or disconnect |
| `PendingUpstreamAuth` | `{user_id, downstream_host}` + `state_id` index | In-flight OAuth state | 5 minutes |
| `UpstreamOAuthClient` | `{type="dcr", issuer, downstream_host}` | Cached DCR registrations | Indefinite |
| `TokenResponse` | `{host, user_id}` | Upstream tokens (static `upstream_oauth2`) | Until expiry or disconnect |

**Key design decisions**:
- `PendingUpstreamAuth` uses `{user_id, downstream_host}` as its primary key,
  so at most one pending auth exists per user per downstream host. A new auth
  flow overwrites the previous one.
- `state_id` is separately indexed for O(1) lookup during the callback
  (`GetPendingUpstreamAuthByState` uses databroker Query with filter).
- `UpstreamOAuthClient` (DCR) is per-instance, not per-user: one registration
  is shared across all users for a given AS+host pair.
- Singleflight keys include `userID` to prevent cross-user token leaks during
  concurrent refresh.

---

## Configuration and Wiring

### Runtime Flag

The `RuntimeFlagMCP` (`config/runtime_flags.go`) gates MCP functionality.
When enabled:
1. The controlplane auto-creates an `UpstreamRequestHandler`
2. MCP well-known routes are added to virtual hosts

### Controlplane Wiring

```mermaid
flowchart TD
    subgraph "controlplane.NewServer()"
        CheckFlag{"RuntimeFlagMCP set?"}
        CreateHandler["NewUpstreamAuthHandlerFromConfig()<br/>→ Storage (databroker)<br/>→ HostInfo (config)<br/>→ HTTP client"]
        CheckHandlerErr{"Handler creation<br/>error?"}
        LogWarn["Log warning<br/>(handler = nil)"]
        CreateExtProc["extproc.NewServer(handler, callback)"]
        RegisterGRPC["Register on GRPCServer"]

        CheckFlag -->|Yes| CreateHandler --> CheckHandlerErr
        CheckHandlerErr -->|Yes| LogWarn --> CreateExtProc
        CheckHandlerErr -->|No| CreateExtProc
        CheckFlag -->|No| CreateExtProc
        CreateExtProc --> RegisterGRPC
    end

    subgraph "Envoy Config Generation"
        BuildFilters["buildMainHTTPConnectionManagerFilter()<br/>→ ExtProcFilter(Disabled: true)"]
        BuildRoutes["buildRouteForPolicyAndMatch()<br/>→ if IsMCPServer: PerFilterConfigExtProcEnabled()"]
        BuildVHosts["buildVirtualHost()<br/>→ if MCP + flag: add well-known routes"]
    end

    RegisterGRPC -.->|"serves gRPC"| BuildFilters
    BuildFilters --> BuildRoutes --> BuildVHosts

    style CheckFlag fill:#fff3e0
```

### HostInfo Resolution

`HostInfo` indexes all MCP policies by downstream hostname at startup (lazy,
via `sync.Once`). It provides the dispatch mechanism for token lookup:

```mermaid
flowchart TD
    Policy["config.Policy<br/>From: https://github.localhost.pomerium.io<br/>To: https://api.github.com<br/>MCP.Server.upstream_oauth2: nil"]

    HostInfo["HostInfo.servers map"]

    ServerHostInfo["ServerHostInfo{<br/>Host: github.localhost.pomerium.io<br/>URL: https://github.localhost.pomerium.io<br/>UpstreamURL: https://api.github.com<br/>RouteID: abc123<br/>AuthorizationServerURL: (optional fallback AS)<br/>Config: nil (auto-discovery)<br/>}"]

    Policy -->|"BuildHostInfo()"| HostInfo
    HostInfo -->|"key: github.localhost.pomerium.io"| ServerHostInfo

    ServerHostInfo -->|"Config == nil"| AutoDisc["UsesAutoDiscovery() = true"]
    ServerHostInfo -->|"Config != nil"| Static["GetOAuth2ConfigForHost() returns config"]
```

Note: Both `UsesAutoDiscovery()` and `GetOAuth2ConfigForHost()` return false/nil
for hosts not present in the servers map (i.e., hosts without MCP policy).

---

## Endpoint Map

All MCP-related HTTP endpoints served by Pomerium:

| Endpoint | Method | Handler | Purpose |
|---|---|---|---|
| `/.well-known/oauth-protected-resource` | GET | `ProtectedResourceMetadata` | Pomerium's PRM document |
| `/.well-known/oauth-authorization-server` | GET | `AuthorizationServerMetadata` | Pomerium's AS metadata |
| `/.pomerium/mcp/register` | POST | `RegisterClient` | RFC 7591 Dynamic Client Registration |
| `/.pomerium/mcp/authorize` | GET | `Authorize` | OAuth 2.1 authorization endpoint |
| `/.pomerium/mcp/token` | POST | `Token` | OAuth 2.1 token endpoint |
| `/.pomerium/mcp/server/oauth/callback` | GET | `OAuthCallback` | Callback for static `upstream_oauth2` flow |
| `/.pomerium/mcp/client/oauth/callback` | GET | `ClientOAuthCallback` | Callback for upstream auto-discovery flow |
| `/.pomerium/mcp/client/metadata.json` | GET | `ClientIDMetadata` | CIMD document for upstream AS |
| `/.pomerium/mcp/routes` | GET | `ListRoutes` | List MCP server routes for a user |
| `/.pomerium/mcp/connect` | GET | `ConnectGet` | Proactive upstream token acquisition |
| `/.pomerium/mcp/routes/disconnect` | POST | `DisconnectRoutes` | Purge upstream tokens |

---

## Key Files

| File | Purpose |
|---|---|
| `internal/mcp/extproc/server.go` | ext_proc gRPC server: `Process()` loop, `extractRouteContext()`, `handleRequestHeaders()`, `handleResponseHeaders()` |
| `internal/mcp/extproc/handler.go` | `UpstreamRequestHandler` interface, `UpstreamAuthAction`, response builders |
| `internal/mcp/upstream_auth.go` | Concrete `UpstreamRequestHandler`: token lookup, 401 handling, `runDiscovery()`, `runUpstreamOAuthSetup()`, DCR, PKCE, refresh |
| `internal/mcp/upstream_discovery.go` | PRM fetch, AS metadata fetch, well-known URL builders, validators (helpers called by `runDiscovery`) |
| `internal/mcp/handler.go` | MCP HTTP handler: endpoint registration, `Handler` struct |
| `internal/mcp/handler_authorization.go` | `/authorize` endpoint: links pending upstream auth to Pomerium auth requests |
| `internal/mcp/handler_client_oauth_callback.go` | Upstream OAuth callback: code exchange, token storage, flow completion |
| `internal/mcp/handler_connect.go` | `/connect` endpoint: proactive upstream token acquisition, `resolveAutoDiscoveryAuth()` |
| `internal/mcp/handler_metadata.go` | Metadata types: `AuthorizationServerMetadata`, `ProtectedResourceMetadata` |
| `internal/mcp/host_info.go` | `HostInfo`: downstream hostname → route config resolution |
| `internal/mcp/storage.go` | `handlerStorage` interface and databroker implementation |
| `internal/mcp/www_authenticate.go` | `ParseWWWAuthenticate`: SFV-based Bearer challenge parsing |
| `authorize/route_context_metadata.go` | `BuildRouteContextMetadata`: produces ext_authz → ext_proc metadata |
| `config/envoyconfig/filters.go` | `ExtProcFilter()`, `ExtAuthzFilter()` definitions |
| `config/envoyconfig/routes.go` | Per-route ext_proc enablement for MCP routes |
| `config/envoyconfig/per_filter_config.go` | `PerFilterConfigExtProcEnabled()` processing mode |
| `internal/controlplane/server.go` | Controlplane wiring: auto-creates handler, registers ext_proc gRPC |
