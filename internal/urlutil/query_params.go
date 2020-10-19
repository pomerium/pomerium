package urlutil

// Common query parameters used to set and send data between Pomerium
// services over HTTP calls and redirects. They are typically used in
// conjunction with a HMAC to ensure authenticity.
const (
	QueryCallbackURI       = "pomerium_callback_uri"
	QueryImpersonateEmail  = "pomerium_impersonate_email"
	QueryImpersonateGroups = "pomerium_impersonate_groups"
	QueryImpersonateAction = "pomerium_impersonate_action"
	QueryIsProgrammatic    = "pomerium_programmatic"
	QueryForwardAuth       = "pomerium_forward_auth"
	QueryPomeriumJWT       = "pomerium_jwt"
	QuerySession           = "pomerium_session"
	QuerySessionEncrypted  = "pomerium_session_encrypted"
	QueryRedirectURI       = "pomerium_redirect_uri"
	QueryForwardAuthURI    = "uri"
)

// URL signature based query params used for verifying the authenticity of a URL.
const (
	QueryHmacExpiry    = "pomerium_expiry"
	QueryHmacIssued    = "pomerium_issued"
	QueryHmacSignature = "pomerium_signature"
)
