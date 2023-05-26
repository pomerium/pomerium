package config

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

// ToPPL converts a policy into Pomerium Policy Language.
func (p *Policy) ToPPL() *parser.Policy {
	ppl := &parser.Policy{}

	allowRule := parser.Rule{Action: parser.ActionAllow}
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
				Data: parser.Object{
					"is": parser.String(ad),
				},
			})
	}
	for _, aic := range p.AllAllowedIDPClaims() {
		var ks []string
		for k := range aic {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			for _, v := range aic[k] {
				bs, _ := json.Marshal(v)
				data, _ := parser.ParseValue(bytes.NewReader(bs))
				allowRule.Or = append(allowRule.Or,
					parser.Criterion{
						Name:    "claim",
						SubPath: k,
						Data:    data,
					})
			}
		}
	}
	for _, au := range p.AllAllowedUsers() {
		allowRule.Or = append(allowRule.Or,
			parser.Criterion{
				Name: "user",
				Data: parser.Object{
					"is": parser.String(au),
				},
			},
			parser.Criterion{
				Name: "email",
				Data: parser.Object{
					"is": parser.String(au),
				},
			})
	}
	ppl.Rules = append(ppl.Rules, allowRule)

	denyRule := parser.Rule{Action: parser.ActionDeny}
	denyRule.Or = append(denyRule.Or,
		parser.Criterion{
			Name: "invalid_client_certificate",
		})
	ppl.Rules = append(ppl.Rules, denyRule)

	// append embedded PPL policy rules
	if p.Policy != nil && p.Policy.Policy != nil {
		ppl.Rules = append(ppl.Rules, p.Policy.Policy.Rules...)
	}

	return ppl
}
