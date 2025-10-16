package endpoints

// well known paths
const (
	PathAuthenticateCallback        = "/oauth2/callback"
	PathDebugPProf                  = "/debug/pprof"
	PathDebugPProfCmdline           = PathDebugPProf + "/cmdline"
	PathDebugPProfProfile           = PathDebugPProf + "/profile"
	PathDebugPProfSymbol            = PathDebugPProf + "/symbol"
	PathDebugPProfTrace             = PathDebugPProf + "/trace"
	PathHealthz                     = "/healthz"
	PathHPKEPublicKey               = PathWellKnownPomerium + "/hpke-public-key"
	PathJWKS                        = PathWellKnownPomerium + "/jwks.json"
	PathMetrics                     = "/metrics"
	PathMetricsEnvoy                = "/metrics/envoy"
	PathPing                        = "/ping"
	PathPomeriumAPI                 = PathPomeriumDashboard + "/" + SubPathAPI
	PathPomeriumAPILogin            = PathPomeriumAPI + "/v1/login"
	PathPomeriumAPIRoutes           = PathPomeriumAPI + "/v1/routes"
	PathPomeriumCallback            = PathPomeriumDashboard + "/callback"
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
	PathPomeriumUser                = PathPomeriumDashboard + "/" + SubPathUser
	PathPomeriumVerifyAccessToken   = PathPomeriumDashboard + "/" + SubPathVerifyAccessToken
	PathPomeriumVerifyIdentityToken = PathPomeriumDashboard + "/" + SubPathVerifyIdentityToken
	PathPomeriumWebAuthn            = PathPomeriumDashboard + "/" + SubPathWebAuthn
	PathReadyz                      = "/readyz"
	PathRobotsTxt                   = "/" + SubPathRobotsTxt
	PathStartupz                    = "/startupz"
	PathStatus                      = "/status"
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
