package criteria

import (
	"bytes"
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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type (
	A = []any
	M = map[string]any
)

var testingNow = time.Date(2021, 5, 11, 13, 43, 0, 0, time.Local)

type (
	Input struct {
		HTTP                     InputHTTP    `json:"http"`
		Session                  InputSession `json:"session"`
		MCP                      InputMCP     `json:"mcp"`
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
	InputMCP struct {
		Method   string            `json:"method,omitempty"`
		ToolCall *InputMCPToolCall `json:"tool_call,omitempty"`
	}

	InputMCPToolCall struct {
		Name string `json:"name"`
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

func makeRecord(object interface {
	proto.Message
	GetId() string
},
) *databroker.Record {
	a := protoutil.NewAny(object)
	return &databroker.Record{
		Type:       a.GetTypeUrl(),
		Id:         object.GetId(),
		Data:       a,
		ModifiedAt: timestamppb.Now(),
	}
}

func makeStructRecord(recordType, recordID string, object any) *databroker.Record {
	s := protoutil.ToStruct(object).GetStructValue()
	return &databroker.Record{
		Type:       recordType,
		Id:         recordID,
		Data:       protoutil.NewAny(s),
		ModifiedAt: timestamppb.Now(),
	}
}

func evaluate(t *testing.T,
	rawPolicy string,
	dataBrokerRecords []*databroker.Record,
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
		}, func(_ rego.BuiltinContext, op1, op2 *ast.Term) (*ast.Term, error) {
			recordType, ok := op1.Value.(ast.String)
			if !ok {
				return nil, fmt.Errorf("invalid type for record_type: %T", op1)
			}

			recordID, ok := op2.Value.(ast.String)
			if !ok {
				return nil, fmt.Errorf("invalid type for record_id: %T", op2)
			}

			for _, record := range dataBrokerRecords {
				if string(recordType) == record.GetType() &&
					string(recordID) == record.GetId() {
					msg, _ := record.GetData().UnmarshalNew()
					bs, _ := json.Marshal(msg)
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
	preparedQuery, err := r.PrepareForEval(t.Context())
	if err != nil {
		t.Log("source:", regoPolicy)
		return nil, err
	}
	resultSet, err := preparedQuery.Eval(t.Context(),
		// set the eval time so we get a consistent result
		rego.EvalTime(testingNow))
	if err != nil {
		t.Log("source:", regoPolicy)
		return nil, err
	}
	if len(resultSet) == 0 {
		return make(rego.Vars), nil
	}
	vars, ok := resultSet[0].Bindings["result"].(map[string]any)
	if !ok {
		return make(rego.Vars), nil
	}
	return vars, nil
}
