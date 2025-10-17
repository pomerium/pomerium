package endpoints

// well known paths
const (
	PathAuthenticateCallback        = "/oauth2/callback"
	PathDebugPProf                  = "/debug/pprof"
	PathDebugPProfCmdline           = "/debug/pprof/cmdline"
	PathDebugPProfProfile           = "/debug/pprof/profile"
	PathDebugPProfSymbol            = "/debug/pprof/symbol"
	PathDebugPProfTrace             = "/debug/pprof/trace"
	PathHealthz                     = "/healthz"
	PathHPKEPublicKey               = "/.well-known/pomerium/hpke-public-key"
	PathJWKS                        = "/.well-known/pomerium/jwks.json"
	PathMetrics                     = "/metrics"
	PathMetricsEnvoy                = "/metrics/envoy"
	PathPing                        = "/ping"
	PathPomeriumAPI                 = "/.pomerium/api"
	PathPomeriumAPILogin            = "/.pomerium/api/v1/login"
	PathPomeriumAPIRoutes           = "/.pomerium/api/v1/routes"
	PathPomeriumCallback            = "/.pomerium/callback"
	PathPomeriumDashboard           = "/.pomerium"
	PathPomeriumDeviceEnrolled      = "/.pomerium/device-enrolled"
	PathPomeriumJWT                 = "/.pomerium/jwt"
	PathPomeriumMCP                 = "/.pomerium/mcp"
	PathPomeriumMCPAuthorize        = "/.pomerium/mcp/authorize"
	PathPomeriumMCPConnect          = "/.pomerium/mcp/connect"
	PathPomeriumMCPRoutes           = "/.pomerium/mcp/routes"
	PathPomeriumRoutes              = "/.pomerium/routes"
	PathPomeriumSignedOut           = "/.pomerium/signed_out"
	PathPomeriumSignIn              = "/.pomerium/sign_in"
	PathPomeriumSignOut             = "/.pomerium/sign_out"
	PathPomeriumUser                = "/.pomerium/user"
	PathPomeriumVerifyAccessToken   = "/.pomerium/verify-access-token"   //nolint:gosec
	PathPomeriumVerifyIdentityToken = "/.pomerium/verify-identity-token" //nolint:gosec
	PathPomeriumWebAuthn            = "/.pomerium/webauthn"
	PathReadyz                      = "/readyz"
	PathRobotsTxt                   = "/robots.txt"
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
