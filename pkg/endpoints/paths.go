package endpoints

// well known paths
const (
	PathPomeriumAPI          = PathPomeriumDashboard + "/" + SubPathAPI
	PathPomeriumAPILogin     = PathPomeriumAPI + "/v1/login"
	PathPomeriumAPIRoutes    = PathPomeriumAPI + "/v1/routes"
	PathAuthenticateCallback = "/oauth2/callback"
	PathDeviceEnrolled       = PathPomeriumDashboard + "/" + SubPathDeviceEnrolled
	PathHPKEPublicKey        = PathWellKnownPomerium + "/hpke-public-key"
	PathJWKS                 = PathWellKnownPomerium + "/jwks.json"
	PathPomeriumDashboard    = "/.pomerium"
	PathRobotsTxt            = "/" + SubPathRobotsTxt
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
	SubPathAPI                 = "api"
	SubPathDeviceEnrolled      = "device-enrolled"
	SubPathRobotsTxt           = "robots.txt"
	SubPathSignedOut           = "signed_out"
	SubPathSignIn              = "sign_in"
	SubPathSignOut             = "sign_out"
	SubPathVerifyAccessToken   = "verify-access-token"
	SubPathVerifyIdentityToken = "verify-identity-token"
	SubPathWebAuthn            = "webauthn"
)
