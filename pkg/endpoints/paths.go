package endpoints

// well known paths
const (
	PathAuthenticateCallback        = "/oauth2/callback"
	PathHPKEPublicKey               = PathWellKnownPomerium + "/hpke-public-key"
	PathJWKS                        = PathWellKnownPomerium + "/jwks.json"
	PathPomeriumAPI                 = PathPomeriumDashboard + "/" + SubPathAPI
	PathPomeriumAPILogin            = PathPomeriumAPI + "/v1/login"
	PathPomeriumAPIRoutes           = PathPomeriumAPI + "/v1/routes"
	PathPomeriumDashboard           = "/.pomerium"
	PathPomeriumDeviceEnrolled      = PathPomeriumDashboard + "/" + SubPathDeviceEnrolled
	PathPomeriumJWT                 = PathPomeriumDashboard + "/" + SubPathJWT
	PathPomeriumMCP                 = PathPomeriumDashboard + "/" + SubPathMCP
	PathPomeriumMCPAuthorize        = PathPomeriumMCP + "/authorize"
	PathPomeriumMCPConnect          = PathPomeriumMCP + "/connect"
	PathPomeriumMCPRoutes           = PathPomeriumMCP + "/routes"
	PathPomeriumRoutes              = PathPomeriumDashboard + "/" + SubPathRoutes
	PathPomeriumSignedOut           = PathPomeriumDashboard + "/" + SubPathSignedOut
	PathPomeriumSignIn              = PathPomeriumDashboard + "/" + SubPathSignIn
	PathPomeriumSignOut             = PathPomeriumDashboard + "/" + SubPathSignOut
	PathPomeriumVerifyAccessToken   = PathPomeriumDashboard + "/" + SubPathVerifyAccessToken
	PathPomeriumVerifyIdentityToken = PathPomeriumDashboard + "/" + SubPathVerifyIdentityToken
	PathPomeriumWebAuthn            = PathPomeriumDashboard + "/" + SubPathWebAuthn
	PathPomeriumUser                = PathPomeriumDashboard + "/" + SubPathUser
	PathRobotsTxt                   = "/" + SubPathRobotsTxt
	PathWellKnownPomerium           = "/.well-known/pomerium"
)

// well known subpaths
const (
	SubPathAPI                 = "api"
	SubPathDeviceEnrolled      = "device-enrolled"
	SubPathJWT                 = "jwt"
	SubPathMCP                 = "mcp"
	SubPathRobotsTxt           = "robots.txt"
	SubPathRoutes              = "routes"
	SubPathSignedOut           = "signed_out"
	SubPathSignIn              = "sign_in"
	SubPathSignOut             = "sign_out"
	SubPathVerifyAccessToken   = "verify-access-token"
	SubPathVerifyIdentityToken = "verify-identity-token"
	SubPathWebAuthn            = "webauthn"
	SubPathUser                = "user"
)
