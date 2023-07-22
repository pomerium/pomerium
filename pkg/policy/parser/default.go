package parser

// AddDefaultClientCertificateRule adds a deny rule to the policy with the
// criterion invalid_client_certificate.
func (p *Policy) AddDefaultClientCertificateRule() {
	denyRule := Rule{Action: ActionDeny}
	denyRule.Or = append(denyRule.Or, Criterion{Name: "invalid_client_certificate"})
	p.Rules = append(p.Rules, denyRule)
}
