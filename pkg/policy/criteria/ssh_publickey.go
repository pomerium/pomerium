package criteria

import (
	"encoding/base64"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"golang.org/x/crypto/ssh"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

var SSHVerifyUserCert = rego.Function3(&rego.Function{
	Name: "ssh_verify_user_cert",
	Decl: types.NewFunction(
		types.Args(types.S, types.S, types.NewArray(nil, types.S)),
		types.B,
	),
}, func(_ rego.BuiltinContext, op1, op2, op3 *ast.Term) (*ast.Term, error) {
	// The first argument should be an ssh principal name.
	principal, ok := op1.Value.(ast.String)
	if !ok {
		return nil, fmt.Errorf("expected string value, got %T", op1.Value)
	}

	// The second argument should be a base64-encoded ssh certificate in the wire format.
	s, ok := op2.Value.(ast.String)
	if !ok {
		return nil, fmt.Errorf("expected string value, got %T", op2.Value)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(string(s))
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return ast.BooleanTerm(false), nil // not an ssh certificate
	}

	// The third argument should be an array of CAs, also base64-encoded in the wire format.
	arr, ok := op3.Value.(*ast.Array)
	if !ok {
		return nil, fmt.Errorf("expected array value, got: %T", op3.Value)
	}
	userCAs := make(map[string]struct{})
	if arr.Iter(func(t *ast.Term) error {
		s, ok := t.Value.(ast.String)
		if !ok {
			return fmt.Errorf("expected string value, got: %T", t.Value)
		}
		userCABytes, err := base64.StdEncoding.DecodeString(string(s))
		if err != nil {
			return err
		}
		userCAs[string(userCABytes)] = struct{}{}
		return nil
	}) != nil {
		return nil, err
	}

	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			_, ok := userCAs[string(auth.Marshal())]
			return ok
		},
	}
	_, err = checker.Authenticate(usernameConnMetadata{username: string(principal)}, cert)
	return ast.BooleanTerm(err == nil), nil
})

type usernameConnMetadata struct {
	ssh.ConnMetadata
	username string
}

func (m usernameConnMetadata) User() string {
	return m.username
}

type sshPublicKeyCriterion struct {
	g *Generator
}

func (sshPublicKeyCriterion) DataType() generator.CriterionDataType {
	return generator.CriterionDataTypeUnknown
}

func (sshPublicKeyCriterion) Name() string {
	return "ssh_publickey"
}

// Converts a single ssh key from the authorized_keys format to base64-encoded wire format.
// Returns an error if the input is not a [parser.String] or the key could not be parsed.
func parseAuthorizedKey(v parser.Value) (*ast.Term, error) {
	s, ok := v.(parser.String)
	if !ok {
		return nil, fmt.Errorf("expected string value, got: %T", v)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s)) //nolint:dogsled
	if err != nil {
		return nil, err
	}
	return ast.StringTerm(base64.StdEncoding.EncodeToString(key.Marshal())), nil
}

// Converts a single ssh key or a list of ssh keys from the authorized_keys format to
// an array of keys in the base64-encoded wire format.
func parseAuthorizedKeys(data parser.Value) (*ast.Term, error) {
	var arr parser.Array
	switch v := data.(type) {
	case parser.String:
		arr = parser.Array{v}
	case parser.Array:
		arr = v
	default:
		return nil, fmt.Errorf("expected string or array of strings, got: %T", data)
	}

	// Convert each key to ssh wire format for comparison.
	keys := make([]*ast.Term, len(arr))
	for i, v := range arr {
		key, err := parseAuthorizedKey(v)
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}
	return ast.NewTerm(ast.NewArray(keys...)), nil
}

func (c sshPublicKeyCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	keys, err := parseAuthorizedKeys(data)
	if err != nil {
		return nil, nil, err
	}

	body := ast.Body{
		ast.Member.Expr(ast.VarTerm("input.ssh.publickey"), keys),
	}

	rule := NewCriterionRule(c.g, c.Name(),
		ReasonSSHPublickeyOK, ReasonSSHPublickeyUnauthorized,
		body)

	return rule, nil, nil
}

func SSHPublicKey(generator *Generator) Criterion {
	return sshPublicKeyCriterion{g: generator}
}

type sshUserCACriterion struct {
	g *Generator
}

func (sshUserCACriterion) DataType() generator.CriterionDataType {
	return generator.CriterionDataTypeUnknown
}

func (sshUserCACriterion) Name() string {
	return "ssh_ca"
}

func (c sshUserCACriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	keys, err := parseAuthorizedKeys(data)
	if err != nil {
		return nil, nil, err
	}

	body := ast.Body{
		ast.Assign.Expr(ast.VarTerm("userCAs"), keys),
		ast.MustParseExpr("ssh_verify_user_cert(input.ssh.username, input.ssh.publickey, userCAs)"),
	}

	rule := NewCriterionRule(c.g, c.Name(),
		ReasonSSHPublickeyOK, ReasonSSHPublickeyUnauthorized,
		body)

	return rule, nil, nil
}

func SSHUserCA(generator *Generator) Criterion {
	return sshUserCACriterion{g: generator}
}

func init() {
	Register(SSHPublicKey)
	Register(SSHUserCA)
}
