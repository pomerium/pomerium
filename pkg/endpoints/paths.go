package endpoints

// well known paths
const (
	PathAuthenticateCallback = "/oauth2/callback"
	PathHPKEPublicKey        = PathWellKnownPomerium + "/hpke-public-key"
	PathJWKS                 = PathWellKnownPomerium + "/jwks.json"
	PathPomeriumDashboard    = "/.pomerium"
	PathSignOut              = PathPomeriumDashboard + "/" + SubPathSignOut
	PathVerifyAccessToken    = PathPomeriumDashboard + "/" + SubPathVerifyAccessToken
	PathVerifyIdentityToken  = PathPomeriumDashboard + "/" + SubPathVerifyIdentityToken
	PathWellKnownPomerium    = "/.well-known/pomerium"
)

// well known subpaths
const (
	SubPathSignOut             = "sign_out"
	SubPathVerifyAccessToken   = "verify-access-token"
	SubPathVerifyIdentityToken = "verify-identity-token"
)
