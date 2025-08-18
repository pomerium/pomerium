package criteria

import (
	"fmt"
	"net"

	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

type sourceIPCriterion struct {
	g *Generator
}

func (c sourceIPCriterion) DataType() CriterionDataType { return generator.CriterionDataTypeUnknown }

func (c sourceIPCriterion) Name() string { return "source_ip" }

func parseIP(v parser.Value) (*ast.Term, error) {
	s, ok := v.(parser.String)
	if !ok {
		return nil, fmt.Errorf("expected string value, got: %T", v)
	}
	// Accept either a CIDR range or single IP.
	value := string(s)
	if _, _, err := net.ParseCIDR(value); err == nil {
		// Already a CIDR range, return as is.
		return ast.StringTerm(value), nil
	} else if ip := net.ParseIP(value); ip == nil {
		// Error: not a CIDR range or IP address.
		return nil, fmt.Errorf("expected IP or CIDR range, got: %q", value)
	} else if ipv4 := ip.To4(); ipv4 != nil {
		ipnet := net.IPNet{
			IP:   ipv4,
			Mask: net.CIDRMask(32, 32),
		}
		return ast.StringTerm(ipnet.String()), nil
	} else {
		ipnet := net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(128, 128),
		}
		return ast.StringTerm(ipnet.String()), nil
	}
}

func parseIPs(data parser.Value) (*ast.Term, error) {
	var arr parser.Array
	switch v := data.(type) {
	case parser.String:
		arr = parser.Array{v}
	case parser.Array:
		arr = v
	default:
		return nil, fmt.Errorf("expected string or array of strings, got: %T", data)
	}

	cidrs := make([]*ast.Term, len(arr))
	for i, v := range arr {
		cidr, err := parseIP(v)
		if err != nil {
			return nil, err
		}
		cidrs[i] = cidr
	}
	return ast.NewTerm(ast.NewArray(cidrs...)), nil
}

func (c sourceIPCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	cidrs, err := parseIPs(data)
	if err != nil {
		return nil, nil, err
	}

	body := ast.Body{
		ast.GreaterThan.Expr(
			ast.Count.Call(
				ast.NetCIDRContainsMatches.Call(cidrs, ast.VarTerm("input.http.ip")),
			),
			ast.IntNumberTerm(0),
		),
	}

	rule := NewCriterionRule(c.g, c.Name(),
		ReasonSourceIPOK, ReasonSourceIPUnauthorized,
		body)

	return rule, nil, nil
}

// SourceIP returns a Criterion which matches source IP address.
func SourceIP(generator *Generator) Criterion {
	return sourceIPCriterion{g: generator}
}

func init() {
	Register(SourceIP)
}
