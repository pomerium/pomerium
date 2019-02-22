# Pomerium Changelog

## Unreleased

FEATURES:

 * **Group Support** : The authenticate service now retrieves a user's group membership information during authentication and refresh. This change may require additional identity provider configuration; all of which are described in the [updated docs](https://www.pomerium.io/docs/identity-providers.html). A brief summary of the requirements for each IdP are as follows:
	- Google requires the [Admin SDK](https://developers.google.com/admin-sdk/directory/) to enabled, a service account with properly delegated access, and `IDP_SERVICE_ACCOUNT` to be set to the base64 encoded value of the service account's key file. 
	- Okta requires a `groups` claim to be added to both the `id_token` and `access_token`. No additional API calls are made. 
	- Microsoft Azure Active Directory requires the application be given an [additional API permission](https://docs.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0), `Directory.Read.All`. 
	- Onelogin requires the [groups](https://developers.onelogin.com/openid-connect/scopes) was supplied during authentication and that groups parameter has been mapped. Group membership is validated on refresh with the [user-info api endpoint](https://developers.onelogin.com/openid-connect/api/user-info). 
 * **WebSocket Support** : With [Go 1.12](https://golang.org/doc/go1.12#net/http/httputil) pomerium automatically proxies WebSocket requests.


CHANGED:

 * Add refresh endpoint `${url}/.pomerium/refresh` which forces a token refresh and responds with the json result. 
 * Group membership added to proxy headers (`x-pomerium-authenticated-user-groups`) and (`x-pomerium-jwt-assertion`).
 * Default Cookie lifetime (`COOKIE_EXPIRE`) changed from 7 days to 14 hours ~ roughly one business day. 
 * Moved identity (`authenticate/providers`) into it's own internal identity package as third party identity providers are going to authorization details (group membership, user role, etc) in addition to just authentication attributes. 
 * Removed circuit breaker package. Calls that were previously wrapped with a circuit breaker fall under gRPC timeouts; which are gated by relatively short deadlines. 
 * Session expiration times are truncated at the second. 
 * **Removed gitlab provider**. We can't support groups until [this gitlab bug](https://gitlab.com/gitlab-org/gitlab-ce/issues/44435#note_88150387) is fixed.
   
IMPROVED:

 * Request context is now maintained throughout request-flow via the [context package](https://golang.org/pkg/context/) enabling deadlines, request tracing, and cancellation. 

FIXED:
 
 * 

SECURITY:
 
 * 