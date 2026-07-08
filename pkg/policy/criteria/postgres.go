package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

type postgresStringCriterion struct {
	g          *Generator
	name       string
	inputRef   *ast.Term
	passReason Reason
	failReason Reason
}

func (postgresStringCriterion) DataType() generator.CriterionDataType {
	return CriterionDataTypeStringMatcher
}

func (c postgresStringCriterion) Name() string {
	return c.name
}

func (c postgresStringCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	var body ast.Body
	if err := matchString(&body, c.inputRef, data); err != nil {
		return nil, nil, err
	}
	return NewCriterionRule(c.g, c.Name(), c.passReason, c.failReason, body), nil, nil
}

func PostgresUsername(generator *Generator) Criterion {
	return postgresStringCriterion{
		g:          generator,
		name:       "postgres_username",
		inputRef:   ast.VarTerm("input.postgres.username"),
		passReason: ReasonPostgresUsernameOK,
		failReason: ReasonPostgresUsernameUnauthorized,
	}
}

func PostgresDatabase(generator *Generator) Criterion {
	return postgresStringCriterion{
		g:          generator,
		name:       "postgres_database",
		inputRef:   ast.VarTerm("input.postgres.database"),
		passReason: ReasonPostgresDatabaseOK,
		failReason: ReasonPostgresDatabaseUnauthorized,
	}
}

func PostgresApplicationName(generator *Generator) Criterion {
	return postgresStringCriterion{
		g:          generator,
		name:       "postgres_application_name",
		inputRef:   ast.VarTerm("input.postgres.application_name"),
		passReason: ReasonPostgresApplicationNameOK,
		failReason: ReasonPostgresApplicationNameUnauthorized,
	}
}

func PostgresStatementClass(generator *Generator) Criterion {
	return postgresStringCriterion{
		g:          generator,
		name:       "postgres_statement_class",
		inputRef:   ast.VarTerm("input.postgres.statement_class"),
		passReason: ReasonPostgresStatementClassOK,
		failReason: ReasonPostgresStatementClassUnauthorized,
	}
}

func init() {
	Register(PostgresUsername)
	Register(PostgresDatabase)
	Register(PostgresApplicationName)
	Register(PostgresStatementClass)
}
