package criteria

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/format"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type (
	A = []interface{}
	M = map[string]interface{}
)

var testingNow = time.Date(2021, 5, 11, 13, 43, 0, 0, time.Local)

type (
	Input struct {
		HTTP                     InputHTTP    `json:"http"`
		Session                  InputSession `json:"session"`
		IsValidClientCertificate bool         `json:"is_valid_client_certificate"`
	}
	InputHTTP struct {
		Method            string                `json:"method"`
		Path              string                `json:"path"`
		Headers           map[string][]string   `json:"headers"`
		ClientCertificate ClientCertificateInfo `json:"client_certificate"`
	}
	InputSession struct {
		ID string `json:"id"`
	}
	ClientCertificateInfo struct {
		Presented bool   `json:"presented"`
		Leaf      string `json:"leaf"`
	}
)

func generateRegoFromYAML(raw string) (string, error) {
	var options []generator.Option
	for _, newMatcher := range All() {
		options = append(options, generator.WithCriterion(newMatcher))
	}

	g := generator.New(options...)
	p := parser.New()
	policy, err := p.ParseYAML(strings.NewReader(raw))
	if err != nil {
		return "", err
	}
	m, err := g.Generate(policy)
	if err != nil {
		return "", err
	}
	bs, err := format.Ast(m)
	if err != nil {
		return "", err
	}
	return string(bs), nil
}

type dataBrokerRecord interface {
	proto.Message
	GetId() string
}

func evaluate(t *testing.T,
	rawPolicy string,
	dataBrokerRecords []dataBrokerRecord,
	input Input,
) (rego.Vars, error) {
	regoPolicy, err := generateRegoFromYAML(rawPolicy)
	if err != nil {
		return nil, fmt.Errorf("error parsing policy: %w", err)
	}

	r := rego.New(
		rego.Module("policy.rego", regoPolicy),
		rego.Query("result = data.pomerium.policy"),
		rego.Function2(&rego.Function{
			Name: "get_databroker_record",
			Decl: types.NewFunction([]types.Type{
				types.S, types.S,
			}, types.A),
		}, func(bctx rego.BuiltinContext, op1, op2 *ast.Term) (*ast.Term, error) {
			recordType, ok := op1.Value.(ast.String)
			if !ok {
				return nil, fmt.Errorf("invalid type for record_type: %T", op1)
			}

			recordID, ok := op2.Value.(ast.String)
			if !ok {
				return nil, fmt.Errorf("invalid type for record_id: %T", op2)
			}

			for _, record := range dataBrokerRecords {
				data := protoutil.NewAny(record)
				if string(recordType) == data.GetTypeUrl() &&
					string(recordID) == record.GetId() {
					bs, _ := json.Marshal(record)
					v, err := ast.ValueFromReader(bytes.NewReader(bs))
					if err != nil {
						return nil, err
					}
					return ast.NewTerm(v), nil
				}
			}

			return nil, nil
		}),
		rego.Input(input),
		rego.SetRegoVersion(ast.RegoV1),
	)
	preparedQuery, err := r.PrepareForEval(context.Background())
	if err != nil {
		t.Log("source:", regoPolicy)
		return nil, err
	}
	resultSet, err := preparedQuery.Eval(context.Background(),
		// set the eval time so we get a consistent result
		rego.EvalTime(testingNow))
	if err != nil {
		t.Log("source:", regoPolicy)
		return nil, err
	}
	if len(resultSet) == 0 {
		return make(rego.Vars), nil
	}
	vars, ok := resultSet[0].Bindings["result"].(map[string]interface{})
	if !ok {
		return make(rego.Vars), nil
	}
	return vars, nil
}
