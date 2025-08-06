package urlutil

// Common query parameters used to set and send data between Pomerium
// services over HTTP calls and redirects. They are typically used in
// conjunction with a HMAC to ensure authenticity.
const (
	QueryAdditionalHosts    = "pomerium_additional_hosts"
	QueryCallbackURI        = "pomerium_callback_uri"
	QueryDeviceCredentialID = "pomerium_device_credential_id"
	QueryDeviceType         = "pomerium_device_type"
	QueryEnrollmentToken    = "pomerium_enrollment_token" //nolint
	QueryExpiry             = "pomerium_expiry"
	QueryIdentityProfile    = "pomerium_identity_profile"
	QueryIdentityProviderID = "pomerium_idp_id"
	QueryIsProgrammatic     = "pomerium_programmatic"
	QueryIssued             = "pomerium_issued"
	QueryPomeriumJWT        = "pomerium_jwt"
	QueryRedirectURI        = "pomerium_redirect_uri"
	QuerySession            = "pomerium_session"
	QuerySessionEncrypted   = "pomerium_session_encrypted"
	QueryBindSession        = "pomerium_bind_session"
	QueryVersion            = "pomerium_version"
	QueryRequestUUID        = "pomerium_request_uuid"
	QueryTraceparent        = "pomerium_traceparent"
	QueryTracestate         = "pomerium_tracestate"
)

// URL signature based query params used for verifying the authenticity of a URL.
const (
	QueryHmacExpiry    = "pomerium_expiry"
	QueryHmacIssued    = "pomerium_issued"
	QueryHmacSignature = "pomerium_signature"
)
