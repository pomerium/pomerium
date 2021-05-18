package config

import (
	"encoding/json"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

// ToPPL converts a policy into Pomerium Policy Language.
func (p *Policy) ToPPL() *parser.Policy {
	ppl := &parser.Policy{}

	allowRule := parser.Rule{Action: parser.ActionAllow}
	allowRule.Or = append(allowRule.Or,
		parser.Criterion{
			Name: "pomerium_routes",
		})
	if p.AllowPublicUnauthenticatedAccess {
		allowRule.Or = append(allowRule.Or,
			parser.Criterion{
				Name: "accept",
				Data: parser.Boolean(true),
			})
	}
	if p.CORSAllowPreflight {
		allowRule.Or = append(allowRule.Or,
			parser.Criterion{
				Name: "cors_preflight",
				Data: parser.Boolean(true),
			})
	}
	if p.AllowAnyAuthenticatedUser {
		allowRule.Or = append(allowRule.Or,
			parser.Criterion{
				Name: "authenticated_user",
				Data: parser.Boolean(true),
			})
	}
	for _, ad := range p.AllAllowedDomains() {
		allowRule.Or = append(allowRule.Or,
			parser.Criterion{
				Name: "domain",
				Data: parser.String(ad),
			})
	}
	for _, ag := range p.AllAllowedGroups() {
		allowRule.Or = append(allowRule.Or,
			parser.Criterion{
				Name: "group",
				Data: parser.String(ag),
			})
	}
	for _, aic := range p.AllAllowedIDPClaims() {
		o := parser.Object{}
		bs, _ := json.Marshal(aic)
		_ = json.Unmarshal(bs, &o)
		allowRule.Or = append(allowRule.Or,
			parser.Criterion{
				Name: "claims",
				Data: o,
			})
	}
	for _, au := range p.AllAllowedUsers() {
		allowRule.Or = append(allowRule.Or,
			parser.Criterion{
				Name: "user",
				Data: parser.String(au),
			},
			parser.Criterion{
				Name: "email",
				Data: parser.String(au),
			})
	}
	ppl.Rules = append(ppl.Rules, allowRule)

	denyRule := parser.Rule{Action: parser.ActionDeny}
	denyRule.Or = append(denyRule.Or,
		parser.Criterion{
			Name: "invalid_client_certificate",
		})
	ppl.Rules = append(ppl.Rules, denyRule)

	return ppl
}
