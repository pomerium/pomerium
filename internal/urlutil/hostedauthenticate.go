package urlutil

// HostedAuthenticateDomains is a list of all known domains associated with the
// hosted authenticate service.
var HostedAuthenticateDomains = []string{
	"authenticate.pomerium.app",
	"authenticate.staging.pomerium.app",
}

var hostedAuthenticateDomainSet = initHostedAuthenticateDomainSet()

func initHostedAuthenticateDomainSet() map[string]struct{} {
	s := make(map[string]struct{})
	for _, domain := range HostedAuthenticateDomains {
		s[domain] = struct{}{}
	}
	return s
}

// IsHostedAuthenticateDomain indicates whether the given domain is associated
// with the hosted authenticate service.
func IsHostedAuthenticateDomain(domain string) bool {
	_, isHostedAuthenticate := hostedAuthenticateDomainSet[domain]
	return isHostedAuthenticate
}
