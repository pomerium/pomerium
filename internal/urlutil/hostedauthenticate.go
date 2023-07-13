package urlutil

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

func IsHostedAuthenticateDomain(domain string) bool {
	_, isHostedAuthenticate := hostedAuthenticateDomainSet[domain]
	return isHostedAuthenticate
}
