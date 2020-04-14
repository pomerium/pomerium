# Changelog

## v0.7.3

### Fixed

- Upgrade gRPC to 1.27.1 @travisgroth (#609)

## v0.7.2

### Changes

- proxy: remove extra session unmarshalling @desimone (#592)
- proxy: add configurable JWT claim headers @travisgroth (#596)
- grpcutil: remove unused pkg @desimone (#593)

### Fixed

- site: fix site on mobile @desimone (#597)

### Documentation

- site: fix site on mobile @desimone (#597)

### Dependency

- chore(deps): update vuepress monorepo to v1.4.0 @renovate (#559)

## v0.7.1

There were no changes in the v0.7.1 release, but we updated the build process slightly.

## v0.7.0

### New

- *: remove import path comments @desimone (#545)
- authenticate: make callback path configurable @desimone (#493)
- authenticate: return 401 for some specific error codes @cuonglm (#561)
- authorization: log audience claim failure @desimone (#553)
- authorize: use jwt instead of state struct @desimone (#514)
- authorize: use opa for policy engine @desimone (#474)
- cmd: add cli to generate service accounts @desimone (#552)
- config: Expose and set default GRPC Server Keepalive Parameters @travisgroth (#509)
- config: Make IDP_PROVIDER env var mandatory @mihaitodor (#536)
- config: Remove superfluous Options.Checksum type conversions @travisgroth (#522)
- gitlab/identity: change group unique identifier to ID @Lumexralph (#571)
- identity: support oidc UserInfo Response @desimone (#529)
- internal/cryptutil: standardize leeway to 5 mins @desimone (#476)
- metrics: Add storage metrics @travisgroth (#554)

### Fixed

- cache: add option validations @desimone (#468)
- config: Add proper yaml tag to Options.Policies @travisgroth (#475)
- ensure correct service name on GRPC related metrics @travisgroth (#510)
- fix group impersonation @desimone (#569)
- fix sign-out bug , fixes #530 @desimone (#544)
- proxy: move set request headers before handle allow public access @ohdarling (#479)
- use service port for session audiences @travisgroth (#562)

### Documentation

- fix `the` typo @ilgooz (#566)
- fix kubernetes dashboard recipe docs @desimone (#504)
- make from source quickstart @desimone (#519)
- update background @desimone (#505)
- update helm for v3 @desimone (#469)
- various fixes @desimone (#478)
- fix cookie_domain @nitper (#472)

### Dependency

- chore(deps): update github.com/pomerium/autocache commit hash to 6c66ed5 @renovate (#480)
- chore(deps): update github.com/pomerium/autocache commit hash to 227c993 @renovate (#537)
- chore(deps): update golang.org/x/crypto commit hash to 0ec3e99 @renovate (#574)
- chore(deps): update golang.org/x/crypto commit hash to 1b76d66 @renovate (#538)
- chore(deps): update golang.org/x/crypto commit hash to 78000ba @renovate (#481)
- chore(deps): update golang.org/x/crypto commit hash to 891825f @renovate (#556)
- chore(deps): update module fatih/color to v1.9.0 @renovate (#575)
- chore(deps): update module fsnotify/fsnotify to v1.4.9 @renovate (#539)
- chore(deps): update module go.etcd.io/bbolt to v1.3.4 @renovate (#557)
- chore(deps): update module go.opencensus.io to v0.22.3 @renovate (#483)
- chore(deps): update module golang/mock to v1.4.0 @renovate (#470)
- chore(deps): update module golang/mock to v1.4.3 @renovate (#540)
- chore(deps): update module golang/protobuf to v1.3.4 @renovate (#485)
- chore(deps): update module golang/protobuf to v1.3.5 @renovate (#541)
- chore(deps): update module google.golang.org/api to v0.20.0 @renovate (#495)
- chore(deps): update module google.golang.org/grpc to v1.27.1 @renovate (#496)
- chore(deps): update module gorilla/mux to v1.7.4 @renovate (#506)
- chore(deps): update module open-policy-agent/opa to v0.17.1 @renovate (#497)
- chore(deps): update module open-policy-agent/opa to v0.17.3 @renovate (#513)
- chore(deps): update module open-policy-agent/opa to v0.18.0 @renovate (#558)
- chore(deps): update module prometheus/client_golang to v1.4.1 @renovate (#498)
- chore(deps): update module prometheus/client_golang to v1.5.0 @renovate (#531)
- chore(deps): update module prometheus/client_golang to v1.5.1 @renovate (#543)
- chore(deps): update module rakyll/statik to v0.1.7 @renovate (#517)
- chore(deps): update module rs/zerolog to v1.18.0 @renovate (#507)
- chore(deps): update module yaml to v2.2.8 @renovate (#471)
- ci: Consolidate matrix build parameters @travisgroth (#521)
- dependency: use go mod redis @desimone (#528)
- deployment: throw away golanglint-ci defaults @desimone (#439)
- deployment: throw away golanglint-ci defaults @desimone (#439)
- deps: enable automerge and set labels on renovate PRs @travisgroth (#527)
- Roll back grpc to v1.25.1 @travisgroth (#484)

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
[gh-100]: https://github.com/pomerium/pomerium/issues/100
[gh-101]: https://github.com/pomerium/pomerium/pull/101
[gh-103]: https://github.com/pomerium/pomerium/issues/103
[gh-108]: https://github.com/pomerium/pomerium/pull/108
[gh-110]: https://github.com/pomerium/pomerium/issues/110
[gh-115]: https://github.com/pomerium/pomerium/issues/115
[gh-116]: https://github.com/pomerium/pomerium/issues/116
[gh-121]: https://github.com/pomerium/pomerium/pull/121
[gh-123]: https://github.com/pomerium/pomerium/pull/123
[gh-128]: https://github.com/pomerium/pomerium/issues/128
[gh-129]: https://github.com/pomerium/pomerium/issues/129
[gh-131]: https://github.com/pomerium/pomerium/pull/131
[gh-132]: https://github.com/pomerium/pomerium/issues/132
[gh-144]: https://github.com/pomerium/pomerium/pull/144
[gh-150]: https://github.com/pomerium/pomerium/pull/150
[gh-151]: https://github.com/pomerium/pomerium/pull/151
[gh-153]: https://github.com/pomerium/pomerium/issues/153
[gh-177]: https://github.com/pomerium/pomerium/pull/177
[gh-179]: https://github.com/pomerium/pomerium/issues/179
[gh-181]: https://github.com/pomerium/pomerium/issues/188
[gh-183]: https://github.com/pomerium/pomerium/pull/183
[gh-190]: https://github.com/pomerium/pomerium/issues/190
[gh-204]: https://github.com/pomerium/pomerium/issues/204
[gh-205]: https://github.com/pomerium/pomerium/issues/205
[gh-211]: https://github.com/pomerium/pomerium/issues/211
[gh-212]: https://github.com/pomerium/pomerium/pull/212
[gh-218]: https://github.com/pomerium/pomerium/pull/218
[gh-219]: https://github.com/pomerium/pomerium/pull/219
[gh-220]: https://github.com/pomerium/pomerium/pull/220
[gh-227]: https://github.com/pomerium/pomerium/pull/227
[gh-230]: https://github.com/pomerium/pomerium/pull/230
[gh-233]: https://github.com/pomerium/pomerium/issues/233
[gh-240]: https://github.com/pomerium/pomerium/pull/240
[gh-259]: https://github.com/pomerium/pomerium/pull/259
[gh-261]: https://github.com/pomerium/pomerium/pull/261
[gh-262]: https://github.com/pomerium/pomerium/issues/262
[gh-266]: https://github.com/pomerium/pomerium/pull/266
[gh-272]: https://github.com/pomerium/pomerium/pull/272
[gh-280]: https://github.com/pomerium/pomerium/issues/280
[gh-284]: https://github.com/pomerium/pomerium/pull/284
[gh-285]: https://github.com/pomerium/pomerium/issues/285
[gh-297]: https://github.com/pomerium/pomerium/pull/297
[gh-303]: https://github.com/pomerium/pomerium/issues/303
[gh-306]: https://github.com/pomerium/pomerium/issues/306
[gh-308]: https://github.com/pomerium/pomerium/issues/308
[gh-314]: https://github.com/pomerium/pomerium/pull/314
[gh-316]: https://github.com/pomerium/pomerium/pull/316
[gh-319]: https://github.com/pomerium/pomerium/issues/319
[gh-328]: https://github.com/pomerium/pomerium/issues/328
[gh-332]: https://github.com/pomerium/pomerium/pull/332/
[gh-338]: https://github.com/pomerium/pomerium/issues/338
[gh-35]: https://github.com/pomerium/pomerium/issues/35
[gh-363]: https://github.com/pomerium/pomerium/issues/363
[gh-376]: https://github.com/pomerium/pomerium/pull/376/
[gh-58]: https://github.com/pomerium/pomerium/issues/58
[gh-69]: https://github.com/pomerium/pomerium/issues/69
[gh-73]: https://github.com/pomerium/pomerium/issues/73
[gh-74]: https://github.com/pomerium/pomerium/pull/74
[gh-79]: https://github.com/pomerium/pomerium/pull/79
[gh-81]: https://github.com/pomerium/pomerium/pull/81
[gh-83]: https://github.com/pomerium/pomerium/pull/83
[gh-92]: https://github.com/pomerium/pomerium/pull/92
[gh-93]: https://github.com/pomerium/pomerium/pull/93
[gh-95]: https://github.com/pomerium/pomerium/pull/95
[gh-96]: https://github.com/pomerium/pomerium/pull/96
[gh-97]: https://github.com/pomerium/pomerium/issues/97
[synology tutorial]: ./quick-start/synology.md
