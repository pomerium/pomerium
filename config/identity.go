package config

import (
	"fmt"
	"slices"
	"strings"

	art "github.com/kralicky/go-adaptive-radix-tree"

	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
)

// GetIdentityProviderForID returns the identity provider associated with the given IDP id.
// If none is found the default provider is returned.
func (o *Options) GetIdentityProviderForID(idpID string) (*identity.Provider, error) {
	for _, p := range o.GetAllPolicies() {
		p := p
		idp, err := o.GetIdentityProviderForPolicy(&p)
		if err != nil {
			return nil, err
		}
		if idp.GetId() == idpID {
			return idp, nil
		}
	}

	return o.GetIdentityProviderForPolicy(nil)
}

// GetIdentityProviderForPolicy gets the identity provider associated with the given policy.
// If policy is nil, or changes none of the default settings, the default provider is returned.
func (o *Options) GetIdentityProviderForPolicy(policy *Policy) (*identity.Provider, error) {
	clientSecret, err := o.GetClientSecret()
	if err != nil {
		return nil, err
	}

	idp := &identity.Provider{
		ClientId:      o.ClientID,
		ClientSecret:  clientSecret,
		Type:          o.Provider,
		Scopes:        o.Scopes,
		Url:           o.ProviderURL,
		RequestParams: o.RequestParams,
	}
	if policy != nil {
		if policy.IDPClientID != "" {
			idp.ClientId = policy.IDPClientID
		}
		if policy.IDPClientSecret != "" {
			idp.ClientSecret = policy.IDPClientSecret
		}
	}
	idp.Id = idp.Hash()
	return idp, nil
}

// GetIdentityProviderForRequestURL gets the identity provider associated with the given request URL.
func (o *Options) GetIdentityProviderForRequestURL(requestURL string) (*identity.Provider, error) {
	u, err := urlutil.ParseAndValidateURL(requestURL)
	if err != nil {
		return nil, err
	}

	for _, p := range o.GetAllPolicies() {
		p := p
		if p.Matches(*u, o.IsRuntimeFlagSet(RuntimeFlagMatchAnyIncomingPort)) {
			return o.GetIdentityProviderForPolicy(&p)
		}
	}
	return o.GetIdentityProviderForPolicy(nil)
}

type PolicyCache struct {
	domainTree art.Tree[domainNode]
}

func NewPolicyCache(options *Options) (*PolicyCache, error) {
	tree := art.New[domainNode]()
	emptyPortMatchesAny := options.IsRuntimeFlagSet(RuntimeFlagMatchAnyIncomingPort)
	for _, policy := range options.GetAllPolicies() {
		u, err := urlutil.ParseAndValidateURL(policy.From)
		if err != nil {
			return nil, err
		}

		urlutil.AllDomainsForURL(u, !emptyPortMatchesAny)(func(host, port string) bool {
			domainKey := radixKeyForHostPort(host, port)
			tree.Update(art.Key(domainKey), func() domainNode {
				return domainNode{policiesByPrefix: art.New[Policy]()}
			}, func(dn *domainNode) {
				if policy.Prefix != "" {
					dn.policiesByPrefix.Insert(art.Key(policy.Prefix), policy)
				} else if policy.Path != "" {
					dn.policiesByPrefix.Insert(art.Key(policy.Path), policy)
				} else if policy.compiledRegex != nil {
					dn.policiesByRegex = append(dn.policiesByRegex, policy)
				} else {
					dn.policiesNoPathMatching = append(dn.policiesNoPathMatching, policy)
				}
			})
			return true
		})
	}
	return &PolicyCache{
		domainTree: tree,
	}, nil
}

func (pc *PolicyCache) GetIdentityProviderForRequestURL(o *Options, requestURL string) (*identity.Provider, error) {
	u, err := urlutil.ParseAndValidateURL(requestURL)
	if err != nil {
		return nil, err
	}

	domainKey := radixKeyForHostPort(u.Hostname(), u.Port())
	domain, ok := pc.domainTree.Resolve(art.Key(domainKey), wildcardResolver)
	if !ok {
		return nil, fmt.Errorf("no identity provider found for request URL %s", requestURL)
	}
	var policy *Policy
	if len(u.Path) > 0 {
		if domain.policiesByPrefix.Size() > 0 {
			actualKey, val, found := domain.policiesByPrefix.SearchNearest(art.Key(u.Path))
			if found {
				// check for prefix match or exact match
				if c := actualKey.Compare(art.Key(u.Path)); c < 0 {
					if val.Prefix != "" && strings.HasPrefix(u.Path, val.Prefix) {
						policy = &val
					}
				} else if c == 0 {
					if val.Path != "" || val.Prefix != "" {
						policy = &val
					}
				}
			}
		}
		if policy == nil {
			for i := range len(domain.policiesByRegex) {
				p := &domain.policiesByRegex[i]
				if p.compiledRegex.MatchString(u.Path) {
					policy = p
					break
				}
			}
		}
	}
	if policy == nil {
		if len(domain.policiesNoPathMatching) > 0 {
			policy = &domain.policiesNoPathMatching[0]
		}
	}
	if policy != nil {
		return o.GetIdentityProviderForPolicy(policy)
	}

	return nil, fmt.Errorf("no identity provider found for request URL %s", requestURL)
}

type domainNode struct {
	policiesByPrefix       art.Tree[Policy]
	policiesByRegex        []Policy
	policiesNoPathMatching []Policy
}

func radixKeyForHostPort(host, port string) string {
	if port == "" {
		port = "*"
	}
	parts := strings.Split(host, ".")
	sb := strings.Builder{}
	sb.WriteString(port)
	for i := len(parts) - 1; i >= 0; i-- {
		sb.WriteByte('.')
		sb.WriteString(parts[i])
	}
	return sb.String()
}

func wildcardResolver(key art.Key, conflictIndex int) (art.Key, int) {
	if conflictIndex >= len(key) {
		return nil, -1
	}
	c := key[conflictIndex]
	if c != '*' && c != '.' {
		nextDot := slices.Index(key[conflictIndex:], '.')
		if nextDot == -1 {
			return art.Key("*"), len(key)
		}
		return art.Key("*"), conflictIndex + nextDot
	}
	return nil, -1
}
