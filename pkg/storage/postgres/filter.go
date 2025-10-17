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
			*query += "("
			*query += "(jsonb_extract_path_text(" + schemaName + "." + recordsTableName + ".data"
			for _, f := range expr.Fields {
				*query += "," + fmt.Sprintf("$%d", len(*args)+1)
				*args = append(*args, f)
			}
			*query += ") = " + fmt.Sprintf("$%d", len(*args)+1) + ")"
			*args = append(*args, expr.Value)
			*query += " OR "
			*query += "(jsonb_extract_path_text(" + schemaName + "." + recordsTableName + ".data"
			for _, f := range expr.Fields {
				*query += "," + fmt.Sprintf("$%d", len(*args)+1)
				*args = append(*args, jsonCamelCase(f))
			}
			*query += ") = " + fmt.Sprintf("$%d", len(*args)+1) + ")"
			*args = append(*args, expr.Value)
			*query += ")"
			return nil
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

// taken from https://github.com/protocolbuffers/protobuf-go/blob/c720882a6fb8f32ad7bfdac1a0ec52ba60a3051b/internal/strs/strings.go#L92
func jsonCamelCase(s string) string {
	var b []byte
	var wasUnderscore bool
	for i := 0; i < len(s); i++ { // proto identifiers are always ASCII
		c := s[i]
		if c != '_' {
			if wasUnderscore && isASCIILower(c) {
				c -= 'a' - 'A' // convert to uppercase
			}
			b = append(b, c)
		}
		wasUnderscore = c == '_'
	}
	return string(b)
}

func isASCIILower(c byte) bool {
	return 'a' <= c && c <= 'z'
}
