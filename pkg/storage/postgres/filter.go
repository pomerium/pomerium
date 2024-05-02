package postgres

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/pomerium/pomerium/pkg/storage"
)

func addFilterExpressionToQuery(query *string, args *[]any, expr storage.FilterExpression) error {
	compoundExpression := func(subexprs []storage.FilterExpression, op string) error {
		*query += "( "
		for i, subexpr := range subexprs {
			if i > 0 {
				*query += " " + op + " "
			}
			err := addFilterExpressionToQuery(query, args, subexpr)
			if err != nil {
				return err
			}
		}
		*query += " )"
		return nil
	}

	switch expr := expr.(type) {
	case storage.AndFilterExpression:
		return compoundExpression(expr, "AND")
	case storage.OrFilterExpression:
		return compoundExpression(expr, "OR")
	case storage.EqualsFilterExpression:
		switch strings.Join(expr.Fields, ".") {
		case "type":
			*query += schemaName + "." + recordsTableName + ".type = " + fmt.Sprintf("$%d", len(*args)+1)
			*args = append(*args, expr.Value)
			return nil
		case "id":
			*query += schemaName + "." + recordsTableName + ".id = " + fmt.Sprintf("$%d", len(*args)+1)
			*args = append(*args, expr.Value)
			return nil
		case "$index":
			if isCIDR(expr.Value) {
				*query += schemaName + "." + recordsTableName + ".index_cidr >>= " + fmt.Sprintf("$%d", len(*args)+1)
				*args = append(*args, expr.Value)
			} else {
				*query += " false "
			}
			return nil
		default:
			return fmt.Errorf("unsupported equals filter: %v", expr.Fields)
		}
	default:
		return fmt.Errorf("unsupported filter expression: %T", expr)
	}
}

func isCIDR(value string) bool {
	if _, err := netip.ParsePrefix(value); err == nil {
		return true
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return true
	}
	return false
}
