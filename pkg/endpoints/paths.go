package endpoints

// well known paths
const (
	PathAuthenticateCallback = "/oauth2/callback"
	PathDeviceEnrolled       = PathPomeriumDashboard + "/" + SubPathDeviceEnrolled
	PathHPKEPublicKey        = PathWellKnownPomerium + "/hpke-public-key"
	PathJWKS                 = PathWellKnownPomerium + "/jwks.json"
	PathPomeriumDashboard    = "/.pomerium"
	PathSignedOut            = PathPomeriumDashboard + "/" + SubPathSignedOut
	PathSignIn               = PathPomeriumDashboard + "/" + SubPathSignIn
	PathSignOut              = PathPomeriumDashboard + "/" + SubPathSignOut
	PathVerifyAccessToken    = PathPomeriumDashboard + "/" + SubPathVerifyAccessToken
	PathVerifyIdentityToken  = PathPomeriumDashboard + "/" + SubPathVerifyIdentityToken
	PathWebAuthn             = PathPomeriumDashboard + "/" + SubPathWebAuthn
	PathWellKnownPomerium    = "/.well-known/pomerium"
)

// well known subpaths
const (
	SubPathDeviceEnrolled      = "device-enrolled"
	SubPathSignedOut           = "signed_out"
	SubPathSignIn              = "sign_in"
	SubPathSignOut             = "sign_out"
	SubPathVerifyAccessToken   = "verify-access-token"
	SubPathVerifyIdentityToken = "verify-identity-token"
	SubPathWebAuthn            = "webauthn"
)
