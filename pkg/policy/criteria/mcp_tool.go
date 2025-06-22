package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

type mcpToolCriterion struct {
	g *Generator
}

func (mcpToolCriterion) DataType() CriterionDataType {
	return CriterionDataTypeStringMatcher
}

func (mcpToolCriterion) Name() string {
	return "mcp_tool"
}

func (c mcpToolCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	r1 := c.g.NewRule(c.Name())
	r1.Head.Value = NewCriterionTerm(true, ReasonMCPNotAToolCall)
	r1.Body = ast.Body{
		ast.MustParseExpr(`input.mcp.method != "tools/call"`),
	}

	r2 := &ast.Rule{
		Head: generator.NewHead("", NewCriterionTerm(true, ReasonMCPToolOK)),
		Body: ast.Body{
			ast.MustParseExpr(`input.mcp.method == "tools/call"`),
		},
	}
	toolRef := ast.RefTerm(ast.VarTerm("input"), ast.VarTerm("mcp"), ast.VarTerm("tool"))
	err := matchString(&r2.Body, toolRef, data)
	if err != nil {
		return nil, nil, err
	}
	r1.Else = r2

	r3 := &ast.Rule{
		Head: generator.NewHead("", NewCriterionTerm(false, ReasonMCPToolUnauthorized)),
		Body: ast.Body{
			ast.MustParseExpr(`input.mcp.method == "tools/call"`),
		},
	}
	r2.Else = r3

	return r1, nil, nil
}

// MCPTool returns a Criterion which matches an MCP tool name.
func MCPTool(generator *Generator) Criterion {
	return mcpToolCriterion{g: generator}
}

func init() {
	Register(MCPTool)
}
