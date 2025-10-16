package endpoints

// well known paths
const (
	PathAuthenticateCallback = "/oauth2/callback"
	PathHPKEPublicKey        = PathWellKnownPomerium + "/hpke-public-key"
	PathJWKS                 = PathWellKnownPomerium + "/jwks.json"
	PathPomeriumDashboard    = "/.pomerium"
	PathWellKnownPomerium    = "/.well-known/pomerium"
)
