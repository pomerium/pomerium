# Pomerium Changelog

## vUNRELEASED

**FEATURES:**

- **Authorization** : The authorization module adds support for per-route access policy. In this release we support the most common forms of identity based access policy: `allowed_users`, `allowed_groups`, and `allowed_domains`. In future versions, the authorization module will also support context and device based authorization policy and decisions. See website documentation for more details.
- **Group Support** : The authenticate service now retrieves a user's group membership information during authentication and refresh. This change may require additional identity provider configuration; all of which are described in the [updated docs](https://www.pomerium.io/docs/identity-providers.html). A brief summary of the requirements for each IdP are as follows:

  - Google requires the [Admin SDK](https://developers.google.com/admin-sdk/directory/) to enabled, a service account with properly delegated access, and `IDP_SERVICE_ACCOUNT` to be set to the base64 encoded value of the service account's key file.
  - Okta requires a `groups` claim to be added to both the `id_token` and `access_token`. No additional API calls are made.
  - Microsoft Azure Active Directory requires the application be given an [additional API permission](https://docs.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0), `Directory.Read.All`.
  - Onelogin requires the [groups](https://developers.onelogin.com/openid-connect/scopes) was supplied during authentication and that groups parameter has been mapped. Group membership is validated on refresh with the [user-info api endpoint](https://developers.onelogin.com/openid-connect/api/user-info).

- **WebSocket Support** : With [Go 1.12](https://golang.org/doc/go1.12#net/http/httputil) pomerium automatically proxies WebSocket requests.

**CHANGED**:
- Add `LOG_LEVEL` config setting that allows for setting the desired minimum log level for an event to be logged. 
- Changed `POMERIUM_DEBUG` config setting to just do console-pretty printing. No longer sets log level.
- Updated `generate_wildcard_cert.sh` to generate a elliptic curve 256 cert by default.
- Updated `env.example` to include a `POLICY` setting example.
- Added `IDP_SERVICE_ACCOUNT` to `env.example` .
- Removed `PROXY_ROOT_DOMAIN` settings which has been replaced by `POLICY`.
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

**FIXED:**

- `http.Server` and `httputil.NewSingleHostReverseProxy` now uses pomerium's logging package instead of the standard library's built in one. [GH-58]
