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
		ast.MustParseExpr(`not input.mcp.method`),
	}

	r2 := &ast.Rule{
		Head: generator.NewHead("", NewCriterionTerm(true, ReasonMCPNotAToolCall)),
		Body: ast.Body{
			ast.MustParseExpr(`input.mcp.method`),
			ast.MustParseExpr(`input.mcp.method != "tools/call"`),
		},
	}
	r1.Else = r2

	r3 := &ast.Rule{
		Head: generator.NewHead("", NewCriterionTerm(true, ReasonMCPToolMatch)),
		Body: ast.Body{
			ast.MustParseExpr(`input.mcp.method == "tools/call"`),
		},
	}
	toolRef := ast.RefTerm(ast.VarTerm("input"), ast.VarTerm("mcp"), ast.VarTerm("tool_call"), ast.VarTerm("name"))
	err := matchString(&r3.Body, toolRef, data)
	if err != nil {
		return nil, nil, err
	}
	r2.Else = r3

	r4 := &ast.Rule{
		Head: generator.NewHead("", NewCriterionTerm(false, ReasonMCPToolNoMatch)),
		Body: ast.Body{
			ast.NewExpr(ast.BooleanTerm(true)),
		},
	}
	r3.Else = r4

	return r1, nil, nil
}

// MCPTool returns a Criterion which matches an MCP tool name.
func MCPTool(generator *Generator) Criterion {
	return mcpToolCriterion{g: generator}
}

func init() {
	Register(MCPTool)
}
