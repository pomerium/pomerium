# Changelog

## v0.7.5

### Fixed

- authorize: fix authorization check for allowed_domains to only match current route @calebdoxsey [GH-624]

## v0.7.4

### Fixed

- pomerium-cli: fix service account cli @desimone [GH-613]

## v0.7.3

### Fixed

- Upgrade gRPC to 1.27.1 @travisgroth [GH-609]

## v0.7.2

### Changes

- proxy: remove extra session unmarshalling @desimone [GH-592]
- proxy: add configurable JWT claim headers @travisgroth [GH-596]
- grpcutil: remove unused pkg @desimone [GH-593]

### Fixed

- site: fix site on mobile @desimone [GH-597]

### Documentation

- site: fix site on mobile @desimone [GH-597]

### Dependency

- chore(deps): update vuepress monorepo to v1.4.0 @renovate [GH-559]

## v0.7.1

There were no changes in the v0.7.1 release, but we updated the build process slightly.

## v0.7.0

### New

- \*: remove import path comments @desimone [GH-545]
- authenticate: make callback path configurable @desimone [GH-493]
- authenticate: return 401 for some specific error codes @cuonglm [GH-561]
- authorization: log audience claim failure @desimone [GH-553]
- authorize: use jwt instead of state struct @desimone [GH-514]
- authorize: use opa for policy engine @desimone [GH-474]
- cmd: add cli to generate service accounts @desimone [GH-552]
- config: Expose and set default GRPC Server Keepalive Parameters @travisgroth [GH-509]
- config: Make IDP_PROVIDER env var mandatory @mihaitodor [GH-536]
- config: Remove superfluous Options.Checksum type conversions @travisgroth [GH-522]
- gitlab/identity: change group unique identifier to ID @Lumexralph [GH-571]
- identity: support oidc UserInfo Response @desimone [GH-529]
- internal/cryptutil: standardize leeway to 5 mins @desimone [GH-476]
- metrics: Add storage metrics @travisgroth [GH-554]

### Fixed

- cache: add option validations @desimone [GH-468]
- config: Add proper yaml tag to Options.Policies @travisgroth [GH-475]
- ensure correct service name on GRPC related metrics @travisgroth [GH-510]
- fix group impersonation @desimone [GH-569]
- fix sign-out bug , fixes #530 @desimone [GH-544]
- proxy: move set request headers before handle allow public access @ohdarling [GH-479]
- use service port for session audiences @travisgroth [GH-562]

### Documentation

- fix `the` typo @ilgooz [GH-566]
- fix kubernetes dashboard recipe docs @desimone [GH-504]
- make from source quickstart @desimone [GH-519]
- update background @desimone [GH-505]
- update helm for v3 @desimone [GH-469]
- various fixes @desimone [GH-478]
- fix cookie_domain @nitper [GH-472]

### Dependency

- chore(deps): update github.com/pomerium/autocache commit hash to 6c66ed5 @renovate [GH-480]
- chore(deps): update github.com/pomerium/autocache commit hash to 227c993 @renovate [GH-537]
- chore(deps): update golang.org/x/crypto commit hash to 0ec3e99 @renovate [GH-574]
- chore(deps): update golang.org/x/crypto commit hash to 1b76d66 @renovate [GH-538]
- chore(deps): update golang.org/x/crypto commit hash to 78000ba @renovate [GH-481]
- chore(deps): update golang.org/x/crypto commit hash to 891825f @renovate [GH-556]
- chore(deps): update module fatih/color to v1.9.0 @renovate [GH-575]
- chore(deps): update module fsnotify/fsnotify to v1.4.9 @renovate [GH-539]
- chore(deps): update module go.etcd.io/bbolt to v1.3.4 @renovate [GH-557]
- chore(deps): update module go.opencensus.io to v0.22.3 @renovate [GH-483]
- chore(deps): update module golang/mock to v1.4.0 @renovate [GH-470]
- chore(deps): update module golang/mock to v1.4.3 @renovate [GH-540]
- chore(deps): update module golang/protobuf to v1.3.4 @renovate [GH-485]
- chore(deps): update module golang/protobuf to v1.3.5 @renovate [GH-541]
- chore(deps): update module google.golang.org/api to v0.20.0 @renovate [GH-495]
- chore(deps): update module google.golang.org/grpc to v1.27.1 @renovate [GH-496]
- chore(deps): update module gorilla/mux to v1.7.4 @renovate [GH-506]
- chore(deps): update module open-policy-agent/opa to v0.17.1 @renovate [GH-497]
- chore(deps): update module open-policy-agent/opa to v0.17.3 @renovate [GH-513]
- chore(deps): update module open-policy-agent/opa to v0.18.0 @renovate [GH-558]
- chore(deps): update module prometheus/client_golang to v1.4.1 @renovate [GH-498]
- chore(deps): update module prometheus/client_golang to v1.5.0 @renovate [GH-531]
- chore(deps): update module prometheus/client_golang to v1.5.1 @renovate [GH-543]
- chore(deps): update module rakyll/statik to v0.1.7 @renovate [GH-517]
- chore(deps): update module rs/zerolog to v1.18.0 @renovate [GH-507]
- chore(deps): update module yaml to v2.2.8 @renovate [GH-471]
- ci: Consolidate matrix build parameters @travisgroth [GH-521]
- dependency: use go mod redis @desimone [GH-528]
- deployment: throw away golanglint-ci defaults @desimone [GH-439]
- deployment: throw away golanglint-ci defaults @desimone [GH-439]
- deps: enable automerge and set labels on renovate PRs @travisgroth [GH-527]
- Roll back grpc to v1.25.1 @travisgroth [GH-484]

## v0.6.0

### New

- authenticate: support backend refresh @desimone [GH-438]
- cache: add cache service @desimone [GH-457]

### Changed

- authorize: consolidate gRPC packages @desimone [GH-443]
- config: added yaml tags to all options struct fields @travisgroth [GH-394],[gh-397]
- config: improved config validation for `shared_secret` @travisgroth [GH-427]
- config: Remove CookieRefresh [GH-428] @u5surf [GH-436]
- config: validate that `shared_key` does not contain whitespace @travisgroth [GH-427]
- httputil : wrap handlers for additional context @desimone [GH-413]

### Fixed

- proxy: fix unauthorized redirect loop for forward auth @desimone [GH-448]
- proxy: fixed regression preventing policy reload [GH-396](https://github.com/pomerium/pomerium/pull/396)

### Documentation

- add cookie settings @danderson [GH-429]
- fix typo in forward auth nginx example @travisgroth [GH-445]
- improved sentence flow and other stuff @Rio [GH-422]
- rename fwdauth to be forwardauth @desimone [GH-447]

### Dependency

- chore(deps): update golang.org/x/crypto commit hash to 61a8779 @renovate [GH-452]
- chore(deps): update golang.org/x/crypto commit hash to 530e935 @renovate [GH-458]
- chore(deps): update golang.org/x/crypto commit hash to 53104e6 @renovate [GH-431]
- chore(deps): update golang.org/x/crypto commit hash to e9b2fee @renovate [GH-414]
- chore(deps): update golang.org/x/oauth2 commit hash to 858c2ad @renovate [GH-415]
- chore(deps): update golang.org/x/oauth2 commit hash to bf48bf1 @renovate [GH-453]
- chore(deps): update module google.golang.org/grpc to v1.26.0 @renovate [GH-433]
- chore(deps): update module google/go-cmp to v0.4.0 @renovate [GH-454]
- chore(deps): update module spf13/viper to v1.6.1 @renovate [GH-423]
- chore(deps): update module spf13/viper to v1.6.2 @renovate [GH-459]
- chore(deps): update module square/go-jose to v2.4.1 @renovate [GH-435]

## v0.5.0

### New

- Session state is now route-scoped. Each managed route uses a transparent, signed JSON Web Token (JWT) to assert identity.
- Managed routes no longer need to be under the same subdomain! Access can be delegated to any route, on any domain.
- Programmatic access now also uses JWT tokens. Access tokens are now generated via a standard oauth2 token flow, and credentials can be refreshed for as long as is permitted by the underlying identity provider.
- User dashboard now pulls in additional user context fields (where supported) like the profile picture, first and last name, and so on.

### Security

- Some identity providers (Okta, Onelogin, and Azure) previously used mutable signifiers to set and assert group membership. Group membership for all providers now use globally unique and immutable identifiers when available.

### Changed

- Azure AD identity provider now uses globally unique and immutable `ID` for [group membership](https://docs.microsoft.com/en-us/graph/api/group-get?view=graph-rest-1.0&tabs=http).
- Okta no longer uses tokens to retrieve group membership. Group membership is now fetched using Okta's HTTP API. [Group membership](https://developer.okta.com/docs/reference/api/groups/) is now determined by the globally unique and immutable `ID` field.
- Okta now requires an additional set of credentials to be used to query for group membership set as a [service account](https://www.pomerium.io/docs/reference/reference.html#identity-provider-service-account).
- URLs are no longer validated to be on the same domain-tree as the authenticate service. Managed routes can live on any domain.
- OneLogin no longer uses tokens to retrieve group membership. Group membership is now fetched using OneLogin's HTTP API. [Group membership](https://developers.onelogin.com/openid-connect/api/user-info/) is now determined by the globally unique and immutable `ID` field.

### Removed

- Force refresh has been removed from the dashboard.
- Previous programmatic authentication endpoints (`/api/v1/token`) has been removed and is no longer supported.

### Fixed

- Fixed an issue where cookie sessions would not clear on error.[GH-376]

## v0.4.2

### Security

- Fixes vulnerabilities fixed in [1.13.2](https://groups.google.com/forum/#!topic/golang-announce/lVEm7llp0w0) including CVE-2019-17596.

## v0.4.1

### Fixed

- Fixed an issue where requests handled by forward-auth would not be redirected back to the underlying route after successful authentication and authorization. [GH-363]
- Fixed an issue where requests handled by forward-auth would add an extraneous query-param following sign-in causing issues in some configurations. [GH-366]

## v0.4.0

### New

- Allow setting request headers on a per route basis in policy. [GH-308]
- Support "forward-auth" integration with third-party ingresses and proxies. [nginx](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/), [nginx-ingress](https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/), and [Traefik](https://docs.traefik.io/middlewares/forwardauth/) are currently supported. [GH-324]
- Add insecure transport / TLS termination support. [GH-328]
- Add setting to override a route's TLS Server Name. [GH-297]
- Pomerium's session can now be passed as a [bearer-auth header](https://tools.ietf.org/html/rfc6750) or [query string](https://en.wikipedia.org/wiki/Query_string) in addition to as a session cookie.
- Add host to the main request logger middleware. [GH-308]
- Add AWS cognito identity provider settings. [GH-314]

### Security

- The user's original intended location before completing the authentication process is now encrypted and kept confidential from the identity provider. [GH-316]
- Under certain circumstances, where debug logging was enabled, pomerium's shared secret could be leaked to http access logs as a query param. [GH-338]

### Fixed

- Fixed an issue where CSRF would fail if multiple tabs were open. [GH-306]
- Fixed an issue where pomerium would clean double slashes from paths. [GH-262]
- Fixed a bug where the impersonate form would persist an empty string for groups value if none set. [GH-303]
- Fixed HTTP redirect server which was not redirecting the correct hostname.

### Changed

- The healthcheck endpoints (`/ping`) now returns the http status `405` StatusMethodNotAllowed for non-`GET` requests.
- Authenticate service no longer uses gRPC.
- The global request logger now captures the full array of proxies from `X-Forwarded-For`, in addition to just the client IP.
- Options code refactored to eliminate global Viper state. [GH-332]
- Pomerium will no longer default to looking for certificates in the root directory. [GH-328]
- Pomerium will validate that either `insecure_server`, or a valid certificate bundle is set. [GH-328]

### Removed

- Removed `AUTHENTICATE_INTERNAL_URL`/`authenticate_internal_url` which is no longer used.

## v0.3.1

### Security

- Fixes vulnerabilities fixed in [Go 1.13.1](https://groups.google.com/forum/m/#!msg/golang-announce/cszieYyuL9Q/g4Z7pKaqAgAJ) including CVE-2019-16276.

## v0.3.0

### New

- GRPC Improvements. [GH-261] / [GH-69]

  - Enable WaitForReady to allow background retries through transient failures
  - Expose a configurable timeout for backend requests to Authorize and Authenticate
  - Enable DNS round_robin load balancing to Authorize and Authenticate services by default

- Add ability to set client certificates for downstream connections. [GH-259]

### Fixed

- Fixed non-`amd64` based docker images.[GH-284]
- Fixed an issue where stripped cookie headers would result in a cookie full of semi-colons (`Cookie: ;;;`). [GH-285]
- HTTP status codes now better adhere to [RFC7235](https://tools.ietf.org/html/rfc7235). In particular, authentication failures reply with [401 Unauthorized](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401) while authorization failures reply with [403 Forbidden](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/403). [GH-272]

### Changed

- Pomerium will now strip `_csrf` cookies in addition to session cookies. [GH-285]
- Disabled gRPC service config. [GH-280]
- A policy's custom certificate authority can set as a file or a base64 encoded blob(`tls_custom_ca`/`tls_custom_ca_file`). [GH-259]

- Remove references to [service named ports](https://golang.org/src/net/lookup.go) and instead use their numeric equivalent. [GH-266]

## v0.2.1

### Security

- Fixes vulnerabilities fixed in [Go 1.12.8](https://groups.google.com/forum/#!topic/golang-nuts/fCQWxqxP8aA) including CVE-2019-9512, CVE-2019-9514 and CVE-2019-14809.

## v0.2.0

### New

#### Telemetry [GH-35]

- **Tracing** [GH-230] aka distributed tracing, provides insight into the full lifecycles, aka traces, of requests to the system, allowing you to pinpoint failures and performance issues.

  - Add [Jaeger](https://opencensus.io/exporters/supported-exporters/go/jaeger/) support. [GH-230]

- **Metrics** provide quantitative information about processes running inside the system, including counters, gauges, and histograms.

  - Add informational metrics. [GH-227]
  - GRPC Metrics Implementation. [GH-218]

    - Additional GRPC server metrics and request sizes
    - Improved GRPC metrics implementation internals
    - The GRPC method label is now 'grpc_method' and GRPC status is now `grpc_client_status` and `grpc_server_status`

  - HTTP Metrics Implementation. [GH-220]

    - Support HTTP request sizes on client and server side of proxy
    - Improved HTTP metrics implementation internals
    - The HTTP method label is now `http_method`, and HTTP status label is now `http_status`

### Changed

- GRPC version upgraded to v1.22 [GH-219]
- Add support for large cookie sessions by chunking. [GH-211]
- Prefer [curve](https://wiki.mozilla.org/Security/Server_Side_TLS) X25519 to P256 for TLS connections. [GH-233]
- Pomerium and its services will gracefully shutdown on [interrupt signal](http://man7.org/linux/man-pages/man7/signal.7.html). [GH-230]
- [Google](https://developers.google.com/identity/protocols/OpenIDConnect) now prompts the user to select a user account (by adding `select_account` to the sign in url). This allows a user who has multiple accounts at the authorization server to select amongst the multiple accounts that they may have current sessions for.

### FIXED

- Fixed potential race condition when signing requests. [GH-240]
- Fixed panic when reloading configuration in single service mode [GH-247]

## v0.1.0

### NEW

- Add programmatic authentication support. [GH-177]
- Add Prometheus format metrics endpoint. [GH-35]
- Add policy setting to enable self-signed certificate support. [GH-179]
- Add policy setting to skip tls certificate verification. [GH-179]

### CHANGED

- Policy `to` and `from` settings must be set to valid HTTP URLs including [schemes](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier) and hostnames (e.g. `http.corp.domain.example` should now be `https://http.corp.domain.example`).
- Proxy's sign out handler `{}/.pomerium/sign_out` now accepts an optional `redirect_uri` parameter which can be used to specify a custom redirect page, so long as it is under the same top-level domain. [GH-183]
- Policy configuration can now be empty at startup. [GH-190]
- Websocket support is now set per-route instead of globally. [GH-204]
- Golint removed from amd64 container. [GH-215]
- Pomerium will error if a session cookie is over 4096 bytes, instead of failing silently. [GH-212]

### FIXED

- Fixed HEADERS environment variable parsing. [GH-188]
- Fixed Azure group lookups. [GH-190]
- If a session is too large (over 4096 bytes) Pomerium will no longer fail silently. [GH-211]
- Internal URLs like dashboard now start auth process to login a user if no session is found. [GH-205].
- When set,`CookieDomain` lets a user set the scope of the user session. CSRF cookies will still always be scoped at the individual route level. [GH-181]

## v0.0.5

### NEW

- Add ability to detect changes and reload policy configuration files. [GH-150]
- Add user dashboard containing information about the current user's session. [GH-123]
- Add functionality allowing users to initiate manual refresh of their session. This is helpful when a user's access control details are updated but their session hasn't updated yet. To prevent abuse, manual refresh is gated by a cooldown (`REFRESH_COOLDOWN`) which defaults to five minutes. [GH-73]
- Add Administrator (super user) account support (`ADMINISTRATORS`). [GH-110]
- Add feature that allows Administrators to impersonate / sign-in as another user from the user dashboard. [GH-110]
- Add docker images and builds for ARM. [GH-95]
- Add support for public, unauthenticated routes. [GH-129]

### CHANGED

- Add Request ID to error pages. [GH-144]
- Refactor configuration handling to use spf13/viper bringing a variety of additional supported storage formats.[GH-115]
- Changed config `AUTHENTICATE_INTERNAL_URL` to be a URL containing both a valid hostname and schema. [GH-153]
- User state is now maintained and scoped at the domain level vs at the route level. [GH-128]
- Error pages contain a link to sign out from the current user session. [GH-100]
- Removed `LifetimeDeadline` from `sessions.SessionState`.
- Removed favicon specific request handling. [GH-131]
- Headers are now configurable via the `HEADERS` configuration variable. [GH-108]
- Refactored proxy and authenticate services to share the same session state cookie. [GH-131]
- Removed instances of extraneous session state saves. [GH-131]
- Changed default behavior when no session is found. Users are now redirected to login instead of being shown an error page.[GH-131]
- Updated routes such that all http handlers are now wrapped with a standard set of middleware. Headers, request id, loggers, and health checks middleware are now applied to all routes including 4xx and 5xx responses. [GH-116]
- Changed docker images to be built from [distroless](https://github.com/GoogleContainerTools/distroless). This fixed an issue with `nsswitch` [GH-97], includes `ca-certificates` and limits the attack surface area of our images. [GH-101]
- Changed HTTP to HTTPS redirect server to be user configurable via `HTTP_REDIRECT_ADDR`. [GH-103]
- `Content-Security-Policy` hash updated to match new UI assets.

### FIXED

- Fixed websocket support. [GH-151]
- Fixed an issue where policy and routes were being pre-processed incorrectly. [GH-132]
- Fixed an issue where `golint` was not being found in our docker image. [GH-121]

## v0.0.4

### CHANGED

- HTTP [Strict Transport Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) is included by default and set to one year. [GH-92]
- HTTP now redirects to HTTPS. [GH-92]
- Removed extraneous `AUTHORIZE_INTERNAL_URL` config option since authorization has no public http handlers, only a gRPC service endpoint. [GH-93]
- Removed `PROXY_ROOT_DOMAIN` config option which is now inferred from `AUTHENTICATE_SERVICE_URL`. Only callback requests originating from a URL on the same sub-domain are permitted. [GH-83]
- Removed `REDIRECT_URL` config option which is now inferred from `AUTHENTICATE_SERVICE_URL` (e.g. `https://$AUTHENTICATE_SERVICE_URL/oauth2/callback`). [GH-83]

### FIXED

- Fixed a bug in the Google provider implementation where the `refresh_token`. Updated the google implementation to use the new `prompt=consent` oauth2 parameters. Reported and fixed by @chemhack [GH-81]

### DOCUMENTATION

- Added [synology tutorial]. [GH-96]
- Added [certificates documentation]. [GH-79]

## v0.0.3

### FEATURES

- **Authorization** : The authorization module adds support for per-route access policy. In this release we support the most common forms of identity based access policy: `allowed_users`, `allowed_groups`, and `allowed_domains`. In future versions, the authorization module will also support context and device based authorization policy and decisions. See website documentation for more details.
- **Group Support** : The authenticate service now retrieves a user's group membership information during authentication and refresh. This change may require additional identity provider configuration; all of which are described in the [updated docs](https://www.pomerium.io/docs/identity-providers.html). A brief summary of the requirements for each IdP are as follows:

  - Google requires the [Admin SDK](https://developers.google.com/admin-sdk/directory/) to enabled, a service account with properly delegated access, and `IDP_SERVICE_ACCOUNT` to be set to the base64 encoded value of the service account's key file.
  - Okta requires a `groups` claim to be added to both the `id_token` and `access_token`. No additional API calls are made.
  - Microsoft Azure Active Directory requires the application be given an [additional API permission](https://docs.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0), `Directory.Read.All`.
  - Onelogin requires the [groups](https://developers.onelogin.com/openid-connect/scopes) was supplied during authentication and that groups parameter has been mapped. Group membership is validated on refresh with the [user-info api endpoint](https://developers.onelogin.com/openid-connect/api/user-info).

- **WebSocket Support** : With [Go 1.12](https://golang.org/doc/go1.12#net/http/httputil) pomerium automatically proxies WebSocket requests.

### CHANGED

- Added `LOG_LEVEL` config setting that allows for setting the desired minimum log level for an event to be logged. [GH-74]
- Changed `POMERIUM_DEBUG` config setting to just do console-pretty printing. No longer sets log level. [GH-74]
- Updated `generate_wildcard_cert.sh` to generate a elliptic curve 256 cert by default.
- Updated `env.example` to include a `POLICY` setting example.
- Added `IDP_SERVICE_ACCOUNT` to `env.example` .
- Removed `ALLOWED_DOMAINS` settings which has been replaced by `POLICY`. Authorization is now handled by the authorization service and is defined in the policy configuration files.
- Removed `ROUTES` settings which has been replaced by `POLICY`.
- Add refresh endpoint `${url}/.pomerium/refresh` which forces a token refresh and responds with the json result.
- Group membership added to proxy headers (`x-pomerium-authenticated-user-groups`) and (`x-pomerium-jwt-assertion`).
- Default Cookie lifetime (`COOKIE_EXPIRE`) changed from 7 days to 14 hours ~ roughly one business day.
- Moved identity (`authenticate/providers`) into its own internal identity package as third party identity providers are going to authorization details (group membership, user role, etc) in addition to just authentication attributes.
- Removed circuit breaker package. Calls that were previously wrapped with a circuit breaker fall under gRPC timeouts; which are gated by relatively short timeouts.
- Session expiration times are truncated at the second.
- **Removed gitlab provider**. We can't support groups until [this gitlab bug](https://gitlab.com/gitlab-org/gitlab-ce/issues/44435#note_88150387) is fixed.
- Request context is now maintained throughout request-flow via the [context package](https://golang.org/pkg/context/) enabling timeouts, request tracing, and cancellation.

### FIXED

- `http.Server` and `httputil.NewSingleHostReverseProxy` now uses pomerium's logging package instead of the standard library's built in one. [GH-58]

[certificates documentation]: ../reference/certificates.md
[gh-1]: https://github.com/pomerium/pomerium/issues/1
[gh-10]: https://github.com/pomerium/pomerium/issues/10
[gh-100]: https://github.com/pomerium/pomerium/issues/100
[gh-101]: https://github.com/pomerium/pomerium/issues/101
[gh-102]: https://github.com/pomerium/pomerium/issues/102
[gh-103]: https://github.com/pomerium/pomerium/issues/103
[gh-104]: https://github.com/pomerium/pomerium/issues/104
[gh-105]: https://github.com/pomerium/pomerium/issues/105
[gh-106]: https://github.com/pomerium/pomerium/issues/106
[gh-107]: https://github.com/pomerium/pomerium/issues/107
[gh-108]: https://github.com/pomerium/pomerium/issues/108
[gh-109]: https://github.com/pomerium/pomerium/issues/109
[gh-11]: https://github.com/pomerium/pomerium/issues/11
[gh-110]: https://github.com/pomerium/pomerium/issues/110
[gh-111]: https://github.com/pomerium/pomerium/issues/111
[gh-112]: https://github.com/pomerium/pomerium/issues/112
[gh-113]: https://github.com/pomerium/pomerium/issues/113
[gh-114]: https://github.com/pomerium/pomerium/issues/114
[gh-115]: https://github.com/pomerium/pomerium/issues/115
[gh-116]: https://github.com/pomerium/pomerium/issues/116
[gh-117]: https://github.com/pomerium/pomerium/issues/117
[gh-118]: https://github.com/pomerium/pomerium/issues/118
[gh-119]: https://github.com/pomerium/pomerium/issues/119
[gh-12]: https://github.com/pomerium/pomerium/issues/12
[gh-120]: https://github.com/pomerium/pomerium/issues/120
[gh-121]: https://github.com/pomerium/pomerium/issues/121
[gh-122]: https://github.com/pomerium/pomerium/issues/122
[gh-123]: https://github.com/pomerium/pomerium/issues/123
[gh-124]: https://github.com/pomerium/pomerium/issues/124
[gh-125]: https://github.com/pomerium/pomerium/issues/125
[gh-126]: https://github.com/pomerium/pomerium/issues/126
[gh-127]: https://github.com/pomerium/pomerium/issues/127
[gh-128]: https://github.com/pomerium/pomerium/issues/128
[gh-129]: https://github.com/pomerium/pomerium/issues/129
[gh-13]: https://github.com/pomerium/pomerium/issues/13
[gh-130]: https://github.com/pomerium/pomerium/issues/130
[gh-131]: https://github.com/pomerium/pomerium/issues/131
[gh-132]: https://github.com/pomerium/pomerium/issues/132
[gh-133]: https://github.com/pomerium/pomerium/issues/133
[gh-134]: https://github.com/pomerium/pomerium/issues/134
[gh-135]: https://github.com/pomerium/pomerium/issues/135
[gh-136]: https://github.com/pomerium/pomerium/issues/136
[gh-137]: https://github.com/pomerium/pomerium/issues/137
[gh-138]: https://github.com/pomerium/pomerium/issues/138
[gh-139]: https://github.com/pomerium/pomerium/issues/139
[gh-14]: https://github.com/pomerium/pomerium/issues/14
[gh-140]: https://github.com/pomerium/pomerium/issues/140
[gh-141]: https://github.com/pomerium/pomerium/issues/141
[gh-142]: https://github.com/pomerium/pomerium/issues/142
[gh-143]: https://github.com/pomerium/pomerium/issues/143
[gh-144]: https://github.com/pomerium/pomerium/issues/144
[gh-145]: https://github.com/pomerium/pomerium/issues/145
[gh-146]: https://github.com/pomerium/pomerium/issues/146
[gh-147]: https://github.com/pomerium/pomerium/issues/147
[gh-148]: https://github.com/pomerium/pomerium/issues/148
[gh-149]: https://github.com/pomerium/pomerium/issues/149
[gh-15]: https://github.com/pomerium/pomerium/issues/15
[gh-150]: https://github.com/pomerium/pomerium/issues/150
[gh-151]: https://github.com/pomerium/pomerium/issues/151
[gh-152]: https://github.com/pomerium/pomerium/issues/152
[gh-153]: https://github.com/pomerium/pomerium/issues/153
[gh-154]: https://github.com/pomerium/pomerium/issues/154
[gh-155]: https://github.com/pomerium/pomerium/issues/155
[gh-156]: https://github.com/pomerium/pomerium/issues/156
[gh-157]: https://github.com/pomerium/pomerium/issues/157
[gh-158]: https://github.com/pomerium/pomerium/issues/158
[gh-159]: https://github.com/pomerium/pomerium/issues/159
[gh-16]: https://github.com/pomerium/pomerium/issues/16
[gh-160]: https://github.com/pomerium/pomerium/issues/160
[gh-161]: https://github.com/pomerium/pomerium/issues/161
[gh-162]: https://github.com/pomerium/pomerium/issues/162
[gh-163]: https://github.com/pomerium/pomerium/issues/163
[gh-164]: https://github.com/pomerium/pomerium/issues/164
[gh-165]: https://github.com/pomerium/pomerium/issues/165
[gh-166]: https://github.com/pomerium/pomerium/issues/166
[gh-167]: https://github.com/pomerium/pomerium/issues/167
[gh-168]: https://github.com/pomerium/pomerium/issues/168
[gh-169]: https://github.com/pomerium/pomerium/issues/169
[gh-17]: https://github.com/pomerium/pomerium/issues/17
[gh-170]: https://github.com/pomerium/pomerium/issues/170
[gh-171]: https://github.com/pomerium/pomerium/issues/171
[gh-172]: https://github.com/pomerium/pomerium/issues/172
[gh-173]: https://github.com/pomerium/pomerium/issues/173
[gh-174]: https://github.com/pomerium/pomerium/issues/174
[gh-175]: https://github.com/pomerium/pomerium/issues/175
[gh-176]: https://github.com/pomerium/pomerium/issues/176
[gh-177]: https://github.com/pomerium/pomerium/issues/177
[gh-178]: https://github.com/pomerium/pomerium/issues/178
[gh-179]: https://github.com/pomerium/pomerium/issues/179
[gh-18]: https://github.com/pomerium/pomerium/issues/18
[gh-180]: https://github.com/pomerium/pomerium/issues/180
[gh-181]: https://github.com/pomerium/pomerium/issues/181
[gh-182]: https://github.com/pomerium/pomerium/issues/182
[gh-183]: https://github.com/pomerium/pomerium/issues/183
[gh-184]: https://github.com/pomerium/pomerium/issues/184
[gh-185]: https://github.com/pomerium/pomerium/issues/185
[gh-186]: https://github.com/pomerium/pomerium/issues/186
[gh-187]: https://github.com/pomerium/pomerium/issues/187
[gh-188]: https://github.com/pomerium/pomerium/issues/188
[gh-189]: https://github.com/pomerium/pomerium/issues/189
[gh-19]: https://github.com/pomerium/pomerium/issues/19
[gh-190]: https://github.com/pomerium/pomerium/issues/190
[gh-191]: https://github.com/pomerium/pomerium/issues/191
[gh-192]: https://github.com/pomerium/pomerium/issues/192
[gh-193]: https://github.com/pomerium/pomerium/issues/193
[gh-194]: https://github.com/pomerium/pomerium/issues/194
[gh-195]: https://github.com/pomerium/pomerium/issues/195
[gh-196]: https://github.com/pomerium/pomerium/issues/196
[gh-197]: https://github.com/pomerium/pomerium/issues/197
[gh-198]: https://github.com/pomerium/pomerium/issues/198
[gh-199]: https://github.com/pomerium/pomerium/issues/199
[gh-2]: https://github.com/pomerium/pomerium/issues/2
[gh-20]: https://github.com/pomerium/pomerium/issues/20
[gh-200]: https://github.com/pomerium/pomerium/issues/200
[gh-201]: https://github.com/pomerium/pomerium/issues/201
[gh-202]: https://github.com/pomerium/pomerium/issues/202
[gh-203]: https://github.com/pomerium/pomerium/issues/203
[gh-204]: https://github.com/pomerium/pomerium/issues/204
[gh-205]: https://github.com/pomerium/pomerium/issues/205
[gh-206]: https://github.com/pomerium/pomerium/issues/206
[gh-207]: https://github.com/pomerium/pomerium/issues/207
[gh-208]: https://github.com/pomerium/pomerium/issues/208
[gh-209]: https://github.com/pomerium/pomerium/issues/209
[gh-21]: https://github.com/pomerium/pomerium/issues/21
[gh-210]: https://github.com/pomerium/pomerium/issues/210
[gh-211]: https://github.com/pomerium/pomerium/issues/211
[gh-212]: https://github.com/pomerium/pomerium/issues/212
[gh-213]: https://github.com/pomerium/pomerium/issues/213
[gh-214]: https://github.com/pomerium/pomerium/issues/214
[gh-215]: https://github.com/pomerium/pomerium/issues/215
[gh-216]: https://github.com/pomerium/pomerium/issues/216
[gh-217]: https://github.com/pomerium/pomerium/issues/217
[gh-218]: https://github.com/pomerium/pomerium/issues/218
[gh-219]: https://github.com/pomerium/pomerium/issues/219
[gh-22]: https://github.com/pomerium/pomerium/issues/22
[gh-220]: https://github.com/pomerium/pomerium/issues/220
[gh-221]: https://github.com/pomerium/pomerium/issues/221
[gh-222]: https://github.com/pomerium/pomerium/issues/222
[gh-223]: https://github.com/pomerium/pomerium/issues/223
[gh-224]: https://github.com/pomerium/pomerium/issues/224
[gh-225]: https://github.com/pomerium/pomerium/issues/225
[gh-226]: https://github.com/pomerium/pomerium/issues/226
[gh-227]: https://github.com/pomerium/pomerium/issues/227
[gh-228]: https://github.com/pomerium/pomerium/issues/228
[gh-229]: https://github.com/pomerium/pomerium/issues/229
[gh-23]: https://github.com/pomerium/pomerium/issues/23
[gh-230]: https://github.com/pomerium/pomerium/issues/230
[gh-231]: https://github.com/pomerium/pomerium/issues/231
[gh-232]: https://github.com/pomerium/pomerium/issues/232
[gh-233]: https://github.com/pomerium/pomerium/issues/233
[gh-234]: https://github.com/pomerium/pomerium/issues/234
[gh-235]: https://github.com/pomerium/pomerium/issues/235
[gh-236]: https://github.com/pomerium/pomerium/issues/236
[gh-237]: https://github.com/pomerium/pomerium/issues/237
[gh-238]: https://github.com/pomerium/pomerium/issues/238
[gh-239]: https://github.com/pomerium/pomerium/issues/239
[gh-24]: https://github.com/pomerium/pomerium/issues/24
[gh-240]: https://github.com/pomerium/pomerium/issues/240
[gh-241]: https://github.com/pomerium/pomerium/issues/241
[gh-242]: https://github.com/pomerium/pomerium/issues/242
[gh-243]: https://github.com/pomerium/pomerium/issues/243
[gh-244]: https://github.com/pomerium/pomerium/issues/244
[gh-245]: https://github.com/pomerium/pomerium/issues/245
[gh-246]: https://github.com/pomerium/pomerium/issues/246
[gh-247]: https://github.com/pomerium/pomerium/issues/247
[gh-248]: https://github.com/pomerium/pomerium/issues/248
[gh-249]: https://github.com/pomerium/pomerium/issues/249
[gh-25]: https://github.com/pomerium/pomerium/issues/25
[gh-250]: https://github.com/pomerium/pomerium/issues/250
[gh-251]: https://github.com/pomerium/pomerium/issues/251
[gh-252]: https://github.com/pomerium/pomerium/issues/252
[gh-253]: https://github.com/pomerium/pomerium/issues/253
[gh-254]: https://github.com/pomerium/pomerium/issues/254
[gh-255]: https://github.com/pomerium/pomerium/issues/255
[gh-256]: https://github.com/pomerium/pomerium/issues/256
[gh-257]: https://github.com/pomerium/pomerium/issues/257
[gh-258]: https://github.com/pomerium/pomerium/issues/258
[gh-259]: https://github.com/pomerium/pomerium/issues/259
[gh-26]: https://github.com/pomerium/pomerium/issues/26
[gh-260]: https://github.com/pomerium/pomerium/issues/260
[gh-261]: https://github.com/pomerium/pomerium/issues/261
[gh-262]: https://github.com/pomerium/pomerium/issues/262
[gh-263]: https://github.com/pomerium/pomerium/issues/263
[gh-264]: https://github.com/pomerium/pomerium/issues/264
[gh-265]: https://github.com/pomerium/pomerium/issues/265
[gh-266]: https://github.com/pomerium/pomerium/issues/266
[gh-267]: https://github.com/pomerium/pomerium/issues/267
[gh-268]: https://github.com/pomerium/pomerium/issues/268
[gh-269]: https://github.com/pomerium/pomerium/issues/269
[gh-27]: https://github.com/pomerium/pomerium/issues/27
[gh-270]: https://github.com/pomerium/pomerium/issues/270
[gh-271]: https://github.com/pomerium/pomerium/issues/271
[gh-272]: https://github.com/pomerium/pomerium/issues/272
[gh-273]: https://github.com/pomerium/pomerium/issues/273
[gh-274]: https://github.com/pomerium/pomerium/issues/274
[gh-275]: https://github.com/pomerium/pomerium/issues/275
[gh-276]: https://github.com/pomerium/pomerium/issues/276
[gh-277]: https://github.com/pomerium/pomerium/issues/277
[gh-278]: https://github.com/pomerium/pomerium/issues/278
[gh-279]: https://github.com/pomerium/pomerium/issues/279
[gh-28]: https://github.com/pomerium/pomerium/issues/28
[gh-280]: https://github.com/pomerium/pomerium/issues/280
[gh-281]: https://github.com/pomerium/pomerium/issues/281
[gh-282]: https://github.com/pomerium/pomerium/issues/282
[gh-283]: https://github.com/pomerium/pomerium/issues/283
[gh-284]: https://github.com/pomerium/pomerium/issues/284
[gh-285]: https://github.com/pomerium/pomerium/issues/285
[gh-286]: https://github.com/pomerium/pomerium/issues/286
[gh-287]: https://github.com/pomerium/pomerium/issues/287
[gh-288]: https://github.com/pomerium/pomerium/issues/288
[gh-289]: https://github.com/pomerium/pomerium/issues/289
[gh-29]: https://github.com/pomerium/pomerium/issues/29
[gh-290]: https://github.com/pomerium/pomerium/issues/290
[gh-291]: https://github.com/pomerium/pomerium/issues/291
[gh-292]: https://github.com/pomerium/pomerium/issues/292
[gh-293]: https://github.com/pomerium/pomerium/issues/293
[gh-294]: https://github.com/pomerium/pomerium/issues/294
[gh-295]: https://github.com/pomerium/pomerium/issues/295
[gh-296]: https://github.com/pomerium/pomerium/issues/296
[gh-297]: https://github.com/pomerium/pomerium/issues/297
[gh-298]: https://github.com/pomerium/pomerium/issues/298
[gh-299]: https://github.com/pomerium/pomerium/issues/299
[gh-3]: https://github.com/pomerium/pomerium/issues/3
[gh-30]: https://github.com/pomerium/pomerium/issues/30
[gh-300]: https://github.com/pomerium/pomerium/issues/300
[gh-301]: https://github.com/pomerium/pomerium/issues/301
[gh-302]: https://github.com/pomerium/pomerium/issues/302
[gh-303]: https://github.com/pomerium/pomerium/issues/303
[gh-304]: https://github.com/pomerium/pomerium/issues/304
[gh-305]: https://github.com/pomerium/pomerium/issues/305
[gh-306]: https://github.com/pomerium/pomerium/issues/306
[gh-307]: https://github.com/pomerium/pomerium/issues/307
[gh-308]: https://github.com/pomerium/pomerium/issues/308
[gh-309]: https://github.com/pomerium/pomerium/issues/309
[gh-31]: https://github.com/pomerium/pomerium/issues/31
[gh-310]: https://github.com/pomerium/pomerium/issues/310
[gh-311]: https://github.com/pomerium/pomerium/issues/311
[gh-312]: https://github.com/pomerium/pomerium/issues/312
[gh-313]: https://github.com/pomerium/pomerium/issues/313
[gh-314]: https://github.com/pomerium/pomerium/issues/314
[gh-315]: https://github.com/pomerium/pomerium/issues/315
[gh-316]: https://github.com/pomerium/pomerium/issues/316
[gh-317]: https://github.com/pomerium/pomerium/issues/317
[gh-318]: https://github.com/pomerium/pomerium/issues/318
[gh-319]: https://github.com/pomerium/pomerium/issues/319
[gh-32]: https://github.com/pomerium/pomerium/issues/32
[gh-320]: https://github.com/pomerium/pomerium/issues/320
[gh-321]: https://github.com/pomerium/pomerium/issues/321
[gh-322]: https://github.com/pomerium/pomerium/issues/322
[gh-323]: https://github.com/pomerium/pomerium/issues/323
[gh-324]: https://github.com/pomerium/pomerium/issues/324
[gh-325]: https://github.com/pomerium/pomerium/issues/325
[gh-326]: https://github.com/pomerium/pomerium/issues/326
[gh-327]: https://github.com/pomerium/pomerium/issues/327
[gh-328]: https://github.com/pomerium/pomerium/issues/328
[gh-329]: https://github.com/pomerium/pomerium/issues/329
[gh-33]: https://github.com/pomerium/pomerium/issues/33
[gh-330]: https://github.com/pomerium/pomerium/issues/330
[gh-331]: https://github.com/pomerium/pomerium/issues/331
[gh-332]: https://github.com/pomerium/pomerium/issues/332
[gh-333]: https://github.com/pomerium/pomerium/issues/333
[gh-334]: https://github.com/pomerium/pomerium/issues/334
[gh-335]: https://github.com/pomerium/pomerium/issues/335
[gh-336]: https://github.com/pomerium/pomerium/issues/336
[gh-337]: https://github.com/pomerium/pomerium/issues/337
[gh-338]: https://github.com/pomerium/pomerium/issues/338
[gh-339]: https://github.com/pomerium/pomerium/issues/339
[gh-34]: https://github.com/pomerium/pomerium/issues/34
[gh-340]: https://github.com/pomerium/pomerium/issues/340
[gh-341]: https://github.com/pomerium/pomerium/issues/341
[gh-342]: https://github.com/pomerium/pomerium/issues/342
[gh-343]: https://github.com/pomerium/pomerium/issues/343
[gh-344]: https://github.com/pomerium/pomerium/issues/344
[gh-345]: https://github.com/pomerium/pomerium/issues/345
[gh-346]: https://github.com/pomerium/pomerium/issues/346
[gh-347]: https://github.com/pomerium/pomerium/issues/347
[gh-348]: https://github.com/pomerium/pomerium/issues/348
[gh-349]: https://github.com/pomerium/pomerium/issues/349
[gh-35]: https://github.com/pomerium/pomerium/issues/35
[gh-350]: https://github.com/pomerium/pomerium/issues/350
[gh-351]: https://github.com/pomerium/pomerium/issues/351
[gh-352]: https://github.com/pomerium/pomerium/issues/352
[gh-353]: https://github.com/pomerium/pomerium/issues/353
[gh-354]: https://github.com/pomerium/pomerium/issues/354
[gh-355]: https://github.com/pomerium/pomerium/issues/355
[gh-356]: https://github.com/pomerium/pomerium/issues/356
[gh-357]: https://github.com/pomerium/pomerium/issues/357
[gh-358]: https://github.com/pomerium/pomerium/issues/358
[gh-359]: https://github.com/pomerium/pomerium/issues/359
[gh-36]: https://github.com/pomerium/pomerium/issues/36
[gh-360]: https://github.com/pomerium/pomerium/issues/360
[gh-361]: https://github.com/pomerium/pomerium/issues/361
[gh-362]: https://github.com/pomerium/pomerium/issues/362
[gh-363]: https://github.com/pomerium/pomerium/issues/363
[gh-364]: https://github.com/pomerium/pomerium/issues/364
[gh-365]: https://github.com/pomerium/pomerium/issues/365
[gh-366]: https://github.com/pomerium/pomerium/issues/366
[gh-367]: https://github.com/pomerium/pomerium/issues/367
[gh-368]: https://github.com/pomerium/pomerium/issues/368
[gh-369]: https://github.com/pomerium/pomerium/issues/369
[gh-37]: https://github.com/pomerium/pomerium/issues/37
[gh-370]: https://github.com/pomerium/pomerium/issues/370
[gh-371]: https://github.com/pomerium/pomerium/issues/371
[gh-372]: https://github.com/pomerium/pomerium/issues/372
[gh-373]: https://github.com/pomerium/pomerium/issues/373
[gh-374]: https://github.com/pomerium/pomerium/issues/374
[gh-375]: https://github.com/pomerium/pomerium/issues/375
[gh-376]: https://github.com/pomerium/pomerium/issues/376
[gh-377]: https://github.com/pomerium/pomerium/issues/377
[gh-378]: https://github.com/pomerium/pomerium/issues/378
[gh-379]: https://github.com/pomerium/pomerium/issues/379
[gh-38]: https://github.com/pomerium/pomerium/issues/38
[gh-380]: https://github.com/pomerium/pomerium/issues/380
[gh-381]: https://github.com/pomerium/pomerium/issues/381
[gh-382]: https://github.com/pomerium/pomerium/issues/382
[gh-383]: https://github.com/pomerium/pomerium/issues/383
[gh-384]: https://github.com/pomerium/pomerium/issues/384
[gh-385]: https://github.com/pomerium/pomerium/issues/385
[gh-386]: https://github.com/pomerium/pomerium/issues/386
[gh-387]: https://github.com/pomerium/pomerium/issues/387
[gh-388]: https://github.com/pomerium/pomerium/issues/388
[gh-389]: https://github.com/pomerium/pomerium/issues/389
[gh-39]: https://github.com/pomerium/pomerium/issues/39
[gh-390]: https://github.com/pomerium/pomerium/issues/390
[gh-391]: https://github.com/pomerium/pomerium/issues/391
[gh-392]: https://github.com/pomerium/pomerium/issues/392
[gh-393]: https://github.com/pomerium/pomerium/issues/393
[gh-394]: https://github.com/pomerium/pomerium/issues/394
[gh-395]: https://github.com/pomerium/pomerium/issues/395
[gh-396]: https://github.com/pomerium/pomerium/issues/396
[gh-397]: https://github.com/pomerium/pomerium/issues/397
[gh-398]: https://github.com/pomerium/pomerium/issues/398
[gh-399]: https://github.com/pomerium/pomerium/issues/399
[gh-4]: https://github.com/pomerium/pomerium/issues/4
[gh-40]: https://github.com/pomerium/pomerium/issues/40
[gh-400]: https://github.com/pomerium/pomerium/issues/400
[gh-401]: https://github.com/pomerium/pomerium/issues/401
[gh-402]: https://github.com/pomerium/pomerium/issues/402
[gh-403]: https://github.com/pomerium/pomerium/issues/403
[gh-404]: https://github.com/pomerium/pomerium/issues/404
[gh-405]: https://github.com/pomerium/pomerium/issues/405
[gh-406]: https://github.com/pomerium/pomerium/issues/406
[gh-407]: https://github.com/pomerium/pomerium/issues/407
[gh-408]: https://github.com/pomerium/pomerium/issues/408
[gh-409]: https://github.com/pomerium/pomerium/issues/409
[gh-41]: https://github.com/pomerium/pomerium/issues/41
[gh-410]: https://github.com/pomerium/pomerium/issues/410
[gh-411]: https://github.com/pomerium/pomerium/issues/411
[gh-412]: https://github.com/pomerium/pomerium/issues/412
[gh-413]: https://github.com/pomerium/pomerium/issues/413
[gh-414]: https://github.com/pomerium/pomerium/issues/414
[gh-415]: https://github.com/pomerium/pomerium/issues/415
[gh-416]: https://github.com/pomerium/pomerium/issues/416
[gh-417]: https://github.com/pomerium/pomerium/issues/417
[gh-418]: https://github.com/pomerium/pomerium/issues/418
[gh-419]: https://github.com/pomerium/pomerium/issues/419
[gh-42]: https://github.com/pomerium/pomerium/issues/42
[gh-420]: https://github.com/pomerium/pomerium/issues/420
[gh-421]: https://github.com/pomerium/pomerium/issues/421
[gh-422]: https://github.com/pomerium/pomerium/issues/422
[gh-423]: https://github.com/pomerium/pomerium/issues/423
[gh-424]: https://github.com/pomerium/pomerium/issues/424
[gh-425]: https://github.com/pomerium/pomerium/issues/425
[gh-426]: https://github.com/pomerium/pomerium/issues/426
[gh-427]: https://github.com/pomerium/pomerium/issues/427
[gh-428]: https://github.com/pomerium/pomerium/issues/428
[gh-429]: https://github.com/pomerium/pomerium/issues/429
[gh-43]: https://github.com/pomerium/pomerium/issues/43
[gh-430]: https://github.com/pomerium/pomerium/issues/430
[gh-431]: https://github.com/pomerium/pomerium/issues/431
[gh-432]: https://github.com/pomerium/pomerium/issues/432
[gh-433]: https://github.com/pomerium/pomerium/issues/433
[gh-434]: https://github.com/pomerium/pomerium/issues/434
[gh-435]: https://github.com/pomerium/pomerium/issues/435
[gh-436]: https://github.com/pomerium/pomerium/issues/436
[gh-437]: https://github.com/pomerium/pomerium/issues/437
[gh-438]: https://github.com/pomerium/pomerium/issues/438
[gh-439]: https://github.com/pomerium/pomerium/issues/439
[gh-44]: https://github.com/pomerium/pomerium/issues/44
[gh-440]: https://github.com/pomerium/pomerium/issues/440
[gh-441]: https://github.com/pomerium/pomerium/issues/441
[gh-442]: https://github.com/pomerium/pomerium/issues/442
[gh-443]: https://github.com/pomerium/pomerium/issues/443
[gh-444]: https://github.com/pomerium/pomerium/issues/444
[gh-445]: https://github.com/pomerium/pomerium/issues/445
[gh-446]: https://github.com/pomerium/pomerium/issues/446
[gh-447]: https://github.com/pomerium/pomerium/issues/447
[gh-448]: https://github.com/pomerium/pomerium/issues/448
[gh-449]: https://github.com/pomerium/pomerium/issues/449
[gh-45]: https://github.com/pomerium/pomerium/issues/45
[gh-450]: https://github.com/pomerium/pomerium/issues/450
[gh-451]: https://github.com/pomerium/pomerium/issues/451
[gh-452]: https://github.com/pomerium/pomerium/issues/452
[gh-453]: https://github.com/pomerium/pomerium/issues/453
[gh-454]: https://github.com/pomerium/pomerium/issues/454
[gh-455]: https://github.com/pomerium/pomerium/issues/455
[gh-456]: https://github.com/pomerium/pomerium/issues/456
[gh-457]: https://github.com/pomerium/pomerium/issues/457
[gh-458]: https://github.com/pomerium/pomerium/issues/458
[gh-459]: https://github.com/pomerium/pomerium/issues/459
[gh-46]: https://github.com/pomerium/pomerium/issues/46
[gh-460]: https://github.com/pomerium/pomerium/issues/460
[gh-461]: https://github.com/pomerium/pomerium/issues/461
[gh-462]: https://github.com/pomerium/pomerium/issues/462
[gh-463]: https://github.com/pomerium/pomerium/issues/463
[gh-464]: https://github.com/pomerium/pomerium/issues/464
[gh-465]: https://github.com/pomerium/pomerium/issues/465
[gh-466]: https://github.com/pomerium/pomerium/issues/466
[gh-467]: https://github.com/pomerium/pomerium/issues/467
[gh-468]: https://github.com/pomerium/pomerium/issues/468
[gh-469]: https://github.com/pomerium/pomerium/issues/469
[gh-47]: https://github.com/pomerium/pomerium/issues/47
[gh-470]: https://github.com/pomerium/pomerium/issues/470
[gh-471]: https://github.com/pomerium/pomerium/issues/471
[gh-472]: https://github.com/pomerium/pomerium/issues/472
[gh-473]: https://github.com/pomerium/pomerium/issues/473
[gh-474]: https://github.com/pomerium/pomerium/issues/474
[gh-475]: https://github.com/pomerium/pomerium/issues/475
[gh-476]: https://github.com/pomerium/pomerium/issues/476
[gh-477]: https://github.com/pomerium/pomerium/issues/477
[gh-478]: https://github.com/pomerium/pomerium/issues/478
[gh-479]: https://github.com/pomerium/pomerium/issues/479
[gh-48]: https://github.com/pomerium/pomerium/issues/48
[gh-480]: https://github.com/pomerium/pomerium/issues/480
[gh-481]: https://github.com/pomerium/pomerium/issues/481
[gh-482]: https://github.com/pomerium/pomerium/issues/482
[gh-483]: https://github.com/pomerium/pomerium/issues/483
[gh-484]: https://github.com/pomerium/pomerium/issues/484
[gh-485]: https://github.com/pomerium/pomerium/issues/485
[gh-486]: https://github.com/pomerium/pomerium/issues/486
[gh-487]: https://github.com/pomerium/pomerium/issues/487
[gh-488]: https://github.com/pomerium/pomerium/issues/488
[gh-489]: https://github.com/pomerium/pomerium/issues/489
[gh-49]: https://github.com/pomerium/pomerium/issues/49
[gh-490]: https://github.com/pomerium/pomerium/issues/490
[gh-491]: https://github.com/pomerium/pomerium/issues/491
[gh-492]: https://github.com/pomerium/pomerium/issues/492
[gh-493]: https://github.com/pomerium/pomerium/issues/493
[gh-494]: https://github.com/pomerium/pomerium/issues/494
[gh-495]: https://github.com/pomerium/pomerium/issues/495
[gh-496]: https://github.com/pomerium/pomerium/issues/496
[gh-497]: https://github.com/pomerium/pomerium/issues/497
[gh-498]: https://github.com/pomerium/pomerium/issues/498
[gh-499]: https://github.com/pomerium/pomerium/issues/499
[gh-5]: https://github.com/pomerium/pomerium/issues/5
[gh-50]: https://github.com/pomerium/pomerium/issues/50
[gh-500]: https://github.com/pomerium/pomerium/issues/500
[gh-501]: https://github.com/pomerium/pomerium/issues/501
[gh-502]: https://github.com/pomerium/pomerium/issues/502
[gh-503]: https://github.com/pomerium/pomerium/issues/503
[gh-504]: https://github.com/pomerium/pomerium/issues/504
[gh-505]: https://github.com/pomerium/pomerium/issues/505
[gh-506]: https://github.com/pomerium/pomerium/issues/506
[gh-507]: https://github.com/pomerium/pomerium/issues/507
[gh-508]: https://github.com/pomerium/pomerium/issues/508
[gh-509]: https://github.com/pomerium/pomerium/issues/509
[gh-51]: https://github.com/pomerium/pomerium/issues/51
[gh-510]: https://github.com/pomerium/pomerium/issues/510
[gh-511]: https://github.com/pomerium/pomerium/issues/511
[gh-512]: https://github.com/pomerium/pomerium/issues/512
[gh-513]: https://github.com/pomerium/pomerium/issues/513
[gh-514]: https://github.com/pomerium/pomerium/issues/514
[gh-515]: https://github.com/pomerium/pomerium/issues/515
[gh-516]: https://github.com/pomerium/pomerium/issues/516
[gh-517]: https://github.com/pomerium/pomerium/issues/517
[gh-518]: https://github.com/pomerium/pomerium/issues/518
[gh-519]: https://github.com/pomerium/pomerium/issues/519
[gh-52]: https://github.com/pomerium/pomerium/issues/52
[gh-520]: https://github.com/pomerium/pomerium/issues/520
[gh-521]: https://github.com/pomerium/pomerium/issues/521
[gh-522]: https://github.com/pomerium/pomerium/issues/522
[gh-523]: https://github.com/pomerium/pomerium/issues/523
[gh-524]: https://github.com/pomerium/pomerium/issues/524
[gh-525]: https://github.com/pomerium/pomerium/issues/525
[gh-526]: https://github.com/pomerium/pomerium/issues/526
[gh-527]: https://github.com/pomerium/pomerium/issues/527
[gh-528]: https://github.com/pomerium/pomerium/issues/528
[gh-529]: https://github.com/pomerium/pomerium/issues/529
[gh-53]: https://github.com/pomerium/pomerium/issues/53
[gh-530]: https://github.com/pomerium/pomerium/issues/530
[gh-531]: https://github.com/pomerium/pomerium/issues/531
[gh-532]: https://github.com/pomerium/pomerium/issues/532
[gh-533]: https://github.com/pomerium/pomerium/issues/533
[gh-534]: https://github.com/pomerium/pomerium/issues/534
[gh-535]: https://github.com/pomerium/pomerium/issues/535
[gh-536]: https://github.com/pomerium/pomerium/issues/536
[gh-537]: https://github.com/pomerium/pomerium/issues/537
[gh-538]: https://github.com/pomerium/pomerium/issues/538
[gh-539]: https://github.com/pomerium/pomerium/issues/539
[gh-54]: https://github.com/pomerium/pomerium/issues/54
[gh-540]: https://github.com/pomerium/pomerium/issues/540
[gh-541]: https://github.com/pomerium/pomerium/issues/541
[gh-542]: https://github.com/pomerium/pomerium/issues/542
[gh-543]: https://github.com/pomerium/pomerium/issues/543
[gh-544]: https://github.com/pomerium/pomerium/issues/544
[gh-545]: https://github.com/pomerium/pomerium/issues/545
[gh-546]: https://github.com/pomerium/pomerium/issues/546
[gh-547]: https://github.com/pomerium/pomerium/issues/547
[gh-548]: https://github.com/pomerium/pomerium/issues/548
[gh-549]: https://github.com/pomerium/pomerium/issues/549
[gh-55]: https://github.com/pomerium/pomerium/issues/55
[gh-550]: https://github.com/pomerium/pomerium/issues/550
[gh-551]: https://github.com/pomerium/pomerium/issues/551
[gh-552]: https://github.com/pomerium/pomerium/issues/552
[gh-553]: https://github.com/pomerium/pomerium/issues/553
[gh-554]: https://github.com/pomerium/pomerium/issues/554
[gh-555]: https://github.com/pomerium/pomerium/issues/555
[gh-556]: https://github.com/pomerium/pomerium/issues/556
[gh-557]: https://github.com/pomerium/pomerium/issues/557
[gh-558]: https://github.com/pomerium/pomerium/issues/558
[gh-559]: https://github.com/pomerium/pomerium/issues/559
[gh-56]: https://github.com/pomerium/pomerium/issues/56
[gh-560]: https://github.com/pomerium/pomerium/issues/560
[gh-561]: https://github.com/pomerium/pomerium/issues/561
[gh-562]: https://github.com/pomerium/pomerium/issues/562
[gh-563]: https://github.com/pomerium/pomerium/issues/563
[gh-564]: https://github.com/pomerium/pomerium/issues/564
[gh-565]: https://github.com/pomerium/pomerium/issues/565
[gh-566]: https://github.com/pomerium/pomerium/issues/566
[gh-567]: https://github.com/pomerium/pomerium/issues/567
[gh-568]: https://github.com/pomerium/pomerium/issues/568
[gh-569]: https://github.com/pomerium/pomerium/issues/569
[gh-57]: https://github.com/pomerium/pomerium/issues/57
[gh-570]: https://github.com/pomerium/pomerium/issues/570
[gh-571]: https://github.com/pomerium/pomerium/issues/571
[gh-572]: https://github.com/pomerium/pomerium/issues/572
[gh-573]: https://github.com/pomerium/pomerium/issues/573
[gh-574]: https://github.com/pomerium/pomerium/issues/574
[gh-575]: https://github.com/pomerium/pomerium/issues/575
[gh-576]: https://github.com/pomerium/pomerium/issues/576
[gh-577]: https://github.com/pomerium/pomerium/issues/577
[gh-578]: https://github.com/pomerium/pomerium/issues/578
[gh-579]: https://github.com/pomerium/pomerium/issues/579
[gh-58]: https://github.com/pomerium/pomerium/issues/58
[gh-580]: https://github.com/pomerium/pomerium/issues/580
[gh-581]: https://github.com/pomerium/pomerium/issues/581
[gh-582]: https://github.com/pomerium/pomerium/issues/582
[gh-583]: https://github.com/pomerium/pomerium/issues/583
[gh-584]: https://github.com/pomerium/pomerium/issues/584
[gh-585]: https://github.com/pomerium/pomerium/issues/585
[gh-586]: https://github.com/pomerium/pomerium/issues/586
[gh-587]: https://github.com/pomerium/pomerium/issues/587
[gh-588]: https://github.com/pomerium/pomerium/issues/588
[gh-589]: https://github.com/pomerium/pomerium/issues/589
[gh-59]: https://github.com/pomerium/pomerium/issues/59
[gh-590]: https://github.com/pomerium/pomerium/issues/590
[gh-591]: https://github.com/pomerium/pomerium/issues/591
[gh-592]: https://github.com/pomerium/pomerium/issues/592
[gh-593]: https://github.com/pomerium/pomerium/issues/593
[gh-594]: https://github.com/pomerium/pomerium/issues/594
[gh-595]: https://github.com/pomerium/pomerium/issues/595
[gh-596]: https://github.com/pomerium/pomerium/issues/596
[gh-597]: https://github.com/pomerium/pomerium/issues/597
[gh-598]: https://github.com/pomerium/pomerium/issues/598
[gh-599]: https://github.com/pomerium/pomerium/issues/599
[gh-6]: https://github.com/pomerium/pomerium/issues/6
[gh-60]: https://github.com/pomerium/pomerium/issues/60
[gh-600]: https://github.com/pomerium/pomerium/issues/600
[gh-601]: https://github.com/pomerium/pomerium/issues/601
[gh-602]: https://github.com/pomerium/pomerium/issues/602
[gh-603]: https://github.com/pomerium/pomerium/issues/603
[gh-604]: https://github.com/pomerium/pomerium/issues/604
[gh-605]: https://github.com/pomerium/pomerium/issues/605
[gh-606]: https://github.com/pomerium/pomerium/issues/606
[gh-607]: https://github.com/pomerium/pomerium/issues/607
[gh-608]: https://github.com/pomerium/pomerium/issues/608
[gh-609]: https://github.com/pomerium/pomerium/issues/609
[gh-61]: https://github.com/pomerium/pomerium/issues/61
[gh-610]: https://github.com/pomerium/pomerium/issues/610
[gh-611]: https://github.com/pomerium/pomerium/issues/611
[gh-612]: https://github.com/pomerium/pomerium/issues/612
[gh-613]: https://github.com/pomerium/pomerium/issues/613
[gh-614]: https://github.com/pomerium/pomerium/issues/614
[gh-615]: https://github.com/pomerium/pomerium/issues/615
[gh-616]: https://github.com/pomerium/pomerium/issues/616
[gh-617]: https://github.com/pomerium/pomerium/issues/617
[gh-618]: https://github.com/pomerium/pomerium/issues/618
[gh-619]: https://github.com/pomerium/pomerium/issues/619
[gh-62]: https://github.com/pomerium/pomerium/issues/62
[gh-620]: https://github.com/pomerium/pomerium/issues/620
[gh-621]: https://github.com/pomerium/pomerium/issues/621
[gh-622]: https://github.com/pomerium/pomerium/issues/622
[gh-623]: https://github.com/pomerium/pomerium/issues/623
[gh-624]: https://github.com/pomerium/pomerium/issues/624
[gh-625]: https://github.com/pomerium/pomerium/issues/625
[gh-626]: https://github.com/pomerium/pomerium/issues/626
[gh-627]: https://github.com/pomerium/pomerium/issues/627
[gh-628]: https://github.com/pomerium/pomerium/issues/628
[gh-629]: https://github.com/pomerium/pomerium/issues/629
[gh-63]: https://github.com/pomerium/pomerium/issues/63
[gh-630]: https://github.com/pomerium/pomerium/issues/630
[gh-631]: https://github.com/pomerium/pomerium/issues/631
[gh-632]: https://github.com/pomerium/pomerium/issues/632
[gh-633]: https://github.com/pomerium/pomerium/issues/633
[gh-634]: https://github.com/pomerium/pomerium/issues/634
[gh-635]: https://github.com/pomerium/pomerium/issues/635
[gh-636]: https://github.com/pomerium/pomerium/issues/636
[gh-637]: https://github.com/pomerium/pomerium/issues/637
[gh-638]: https://github.com/pomerium/pomerium/issues/638
[gh-639]: https://github.com/pomerium/pomerium/issues/639
[gh-64]: https://github.com/pomerium/pomerium/issues/64
[gh-640]: https://github.com/pomerium/pomerium/issues/640
[gh-641]: https://github.com/pomerium/pomerium/issues/641
[gh-642]: https://github.com/pomerium/pomerium/issues/642
[gh-643]: https://github.com/pomerium/pomerium/issues/643
[gh-644]: https://github.com/pomerium/pomerium/issues/644
[gh-645]: https://github.com/pomerium/pomerium/issues/645
[gh-646]: https://github.com/pomerium/pomerium/issues/646
[gh-647]: https://github.com/pomerium/pomerium/issues/647
[gh-648]: https://github.com/pomerium/pomerium/issues/648
[gh-649]: https://github.com/pomerium/pomerium/issues/649
[gh-65]: https://github.com/pomerium/pomerium/issues/65
[gh-650]: https://github.com/pomerium/pomerium/issues/650
[gh-651]: https://github.com/pomerium/pomerium/issues/651
[gh-652]: https://github.com/pomerium/pomerium/issues/652
[gh-653]: https://github.com/pomerium/pomerium/issues/653
[gh-654]: https://github.com/pomerium/pomerium/issues/654
[gh-655]: https://github.com/pomerium/pomerium/issues/655
[gh-656]: https://github.com/pomerium/pomerium/issues/656
[gh-657]: https://github.com/pomerium/pomerium/issues/657
[gh-658]: https://github.com/pomerium/pomerium/issues/658
[gh-659]: https://github.com/pomerium/pomerium/issues/659
[gh-66]: https://github.com/pomerium/pomerium/issues/66
[gh-660]: https://github.com/pomerium/pomerium/issues/660
[gh-661]: https://github.com/pomerium/pomerium/issues/661
[gh-662]: https://github.com/pomerium/pomerium/issues/662
[gh-663]: https://github.com/pomerium/pomerium/issues/663
[gh-664]: https://github.com/pomerium/pomerium/issues/664
[gh-665]: https://github.com/pomerium/pomerium/issues/665
[gh-666]: https://github.com/pomerium/pomerium/issues/666
[gh-667]: https://github.com/pomerium/pomerium/issues/667
[gh-668]: https://github.com/pomerium/pomerium/issues/668
[gh-669]: https://github.com/pomerium/pomerium/issues/669
[gh-67]: https://github.com/pomerium/pomerium/issues/67
[gh-670]: https://github.com/pomerium/pomerium/issues/670
[gh-671]: https://github.com/pomerium/pomerium/issues/671
[gh-672]: https://github.com/pomerium/pomerium/issues/672
[gh-673]: https://github.com/pomerium/pomerium/issues/673
[gh-674]: https://github.com/pomerium/pomerium/issues/674
[gh-675]: https://github.com/pomerium/pomerium/issues/675
[gh-676]: https://github.com/pomerium/pomerium/issues/676
[gh-677]: https://github.com/pomerium/pomerium/issues/677
[gh-678]: https://github.com/pomerium/pomerium/issues/678
[gh-679]: https://github.com/pomerium/pomerium/issues/679
[gh-68]: https://github.com/pomerium/pomerium/issues/68
[gh-69]: https://github.com/pomerium/pomerium/issues/69
[gh-7]: https://github.com/pomerium/pomerium/issues/7
[gh-70]: https://github.com/pomerium/pomerium/issues/70
[gh-71]: https://github.com/pomerium/pomerium/issues/71
[gh-72]: https://github.com/pomerium/pomerium/issues/72
[gh-73]: https://github.com/pomerium/pomerium/issues/73
[gh-74]: https://github.com/pomerium/pomerium/issues/74
[gh-75]: https://github.com/pomerium/pomerium/issues/75
[gh-76]: https://github.com/pomerium/pomerium/issues/76
[gh-77]: https://github.com/pomerium/pomerium/issues/77
[gh-78]: https://github.com/pomerium/pomerium/issues/78
[gh-79]: https://github.com/pomerium/pomerium/issues/79
[gh-8]: https://github.com/pomerium/pomerium/issues/8
[gh-80]: https://github.com/pomerium/pomerium/issues/80
[gh-81]: https://github.com/pomerium/pomerium/issues/81
[gh-82]: https://github.com/pomerium/pomerium/issues/82
[gh-83]: https://github.com/pomerium/pomerium/issues/83
[gh-84]: https://github.com/pomerium/pomerium/issues/84
[gh-85]: https://github.com/pomerium/pomerium/issues/85
[gh-86]: https://github.com/pomerium/pomerium/issues/86
[gh-87]: https://github.com/pomerium/pomerium/issues/87
[gh-88]: https://github.com/pomerium/pomerium/issues/88
[gh-89]: https://github.com/pomerium/pomerium/issues/89
[gh-9]: https://github.com/pomerium/pomerium/issues/9
[gh-90]: https://github.com/pomerium/pomerium/issues/90
[gh-91]: https://github.com/pomerium/pomerium/issues/91
[gh-92]: https://github.com/pomerium/pomerium/issues/92
[gh-93]: https://github.com/pomerium/pomerium/issues/93
[gh-94]: https://github.com/pomerium/pomerium/issues/94
[gh-95]: https://github.com/pomerium/pomerium/issues/95
[gh-96]: https://github.com/pomerium/pomerium/issues/96
[gh-97]: https://github.com/pomerium/pomerium/issues/97
[gh-98]: https://github.com/pomerium/pomerium/issues/98
[gh-99]: https://github.com/pomerium/pomerium/issues/99
[synology tutorial]: ./quick-start/synology.md
