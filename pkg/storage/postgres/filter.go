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
		equalExpr := strings.Join(expr.Fields, ".")
		switch equalExpr {
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
			keyPath := strings.Join(expr.Fields, ".")
			var sb strings.Builder
			sb.WriteString("(")
			sb.WriteString(fmt.Sprintf("jsonb_extract_path_text(%s.%s.data", schemaName, recordsTableName))
			fqkeyPath := strings.Split(strings.ReplaceAll(keyPath, ".", ","), ",")
			n := len(fqkeyPath)
			for idx, key := range fqkeyPath {
				sb.WriteString(",")
				jsonKey := jsonCamelCase(key)
				sb.WriteString(fmt.Sprintf("$%d", len(*args)+1))
				*args = append(*args, jsonKey)
				if idx == n-1 {
					sb.WriteString(")")
					sb.WriteString(" = ")
					sb.WriteString(fmt.Sprintf("$%d", len(*args)+1))
					*args = append(*args, expr.Value)
				}
			}
			sb.WriteString(")")
			*query += sb.String()
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

// Source : https://github.com/protocolbuffers/protobuf-go/blob/d65e1d490c91cecb040049dd09d1ac866bc2ce3a/internal/strs/strings.go#L90-L107
// jsonCamelCase converts a snake_case identifier to a camelCase identifier,
// according to the protobuf JSON specification.
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
