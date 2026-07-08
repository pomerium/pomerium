package postgresproxy

import "strings"

func classifySQL(sql string) string {
	s, ok := stripLeadingSQLComments(sql)
	if !ok {
		return "UNKNOWN"
	}
	tokens := sqlKeywordTokens(s, 0)
	if len(tokens) == 0 {
		return "EMPTY"
	}
	first := tokens[0]
	if first == "SELECT" {
		if containsKeyword(tokens, "INTO") {
			return "SELECT_INTO"
		}
		if containsKeywordSequence(tokens, "FOR", "UPDATE") ||
			containsKeywordSequence(tokens, "FOR", "NO") ||
			containsKeywordSequence(tokens, "FOR", "SHARE") ||
			containsKeywordSequence(tokens, "FOR", "KEY") {
			return "SELECT_FOR_LOCK"
		}
	}
	if first == "WITH" && len(tokens) > 1 {
		return "WITH"
	}
	if first == "SET" && len(tokens) > 1 {
		idx := 1
		if tokens[idx] == "SESSION" && len(tokens) > idx+1 && tokens[idx+1] == "AUTHORIZATION" {
			return "SET_SESSION_AUTHORIZATION"
		}
		if tokens[idx] == "LOCAL" || tokens[idx] == "SESSION" {
			idx++
		}
		if len(tokens) > idx && tokens[idx] == "ROLE" {
			return "SET_ROLE"
		}
		if len(tokens) > idx && tokens[idx] == "SESSION_AUTHORIZATION" {
			return "SET_SESSION_AUTHORIZATION"
		}
		if len(tokens) > idx+1 && tokens[idx] == "SESSION" && tokens[idx+1] == "AUTHORIZATION" {
			return "SET_SESSION_AUTHORIZATION"
		}
	}
	if first == "RESET" && len(tokens) > 1 {
		if tokens[1] == "ROLE" {
			return "RESET_ROLE"
		}
		if len(tokens) > 2 && tokens[1] == "SESSION" && tokens[2] == "AUTHORIZATION" {
			return "RESET_SESSION_AUTHORIZATION"
		}
		if tokens[1] == "ALL" {
			return "RESET_ALL"
		}
	}
	return first
}

func sqlKeywordTokens(sql string, max int) []string {
	var tokens []string
	for i := 0; i < len(sql) && (max <= 0 || len(tokens) < max); {
		switch {
		case isSQLSpace(sql[i]) || sql[i] == '(' || sql[i] == ')' || sql[i] == ',' || sql[i] == ';':
			i++
		case strings.HasPrefix(sql[i:], "--"):
			i = skipLineComment(sql, i)
		case strings.HasPrefix(sql[i:], "/*"):
			next, ok := skipBlockComment(sql, i)
			if !ok {
				return tokens
			}
			i = next
		case sql[i] == '\'':
			i = skipSingleQuoted(sql, i)
		case sql[i] == '"':
			i = skipDoubleQuoted(sql, i)
		case sql[i] == '$':
			if tag, ok := readDollarQuoteTag(sql, i); ok {
				if next := strings.Index(sql[i+len(tag):], tag); next >= 0 {
					i += len(tag) + next + len(tag)
					continue
				}
			}
			i++
		case isSQLIdentStart(sql[i]):
			start := i
			i++
			for i < len(sql) && isSQLIdentPart(sql[i]) {
				i++
			}
			tokens = append(tokens, strings.ToUpper(sql[start:i]))
		default:
			i++
		}
	}
	return tokens
}

func containsKeyword(tokens []string, keyword string) bool {
	for _, token := range tokens {
		if token == keyword {
			return true
		}
	}
	return false
}

func containsKeywordSequence(tokens []string, first, second string) bool {
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i] == first && tokens[i+1] == second {
			return true
		}
	}
	return false
}

func skipLineComment(sql string, start int) int {
	i := strings.IndexByte(sql[start:], '\n')
	if i < 0 {
		return len(sql)
	}
	return start + i + 1
}

func skipBlockComment(sql string, start int) (int, bool) {
	if !strings.HasPrefix(sql[start:], "/*") {
		return start, false
	}
	depth := 1
	for i := start + 2; i+1 < len(sql); {
		switch {
		case strings.HasPrefix(sql[i:], "/*"):
			depth++
			i += 2
		case strings.HasPrefix(sql[i:], "*/"):
			depth--
			i += 2
			if depth == 0 {
				return i, true
			}
		default:
			i++
		}
	}
	return len(sql), false
}

func skipSingleQuoted(sql string, start int) int {
	for i := start + 1; i < len(sql); i++ {
		if sql[i] == '\'' {
			if i+1 < len(sql) && sql[i+1] == '\'' {
				i++
				continue
			}
			return i + 1
		}
	}
	return len(sql)
}

func skipDoubleQuoted(sql string, start int) int {
	for i := start + 1; i < len(sql); i++ {
		if sql[i] == '"' {
			if i+1 < len(sql) && sql[i+1] == '"' {
				i++
				continue
			}
			return i + 1
		}
	}
	return len(sql)
}

func isSQLSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\f':
		return true
	default:
		return false
	}
}

func isSQLIdentStart(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func isSQLIdentPart(b byte) bool {
	return isSQLIdentStart(b) || b >= '0' && b <= '9'
}

func stripLeadingSQLComments(sql string) (string, bool) {
	for {
		s := strings.TrimSpace(sql)
		switch {
		case strings.HasPrefix(s, "--"):
			i := strings.IndexByte(s, '\n')
			if i < 0 {
				return "", true
			}
			sql = s[i+1:]
		case strings.HasPrefix(s, "/*"):
			i, ok := skipBlockComment(s, 0)
			if !ok {
				return "", false
			}
			sql = s[i:]
		default:
			return s, true
		}
	}
}

func hasMultipleStatements(sql string) bool {
	const (
		stateNormal = iota
		stateSingleQuote
		stateDoubleQuote
		stateLineComment
		stateBlockComment
		stateDollarQuote
	)
	state := stateNormal
	blockDepth := 0
	dollarTag := ""
	for i := 0; i < len(sql); i++ {
		switch state {
		case stateNormal:
			switch {
			case strings.HasPrefix(sql[i:], "--"):
				state = stateLineComment
				i++
			case strings.HasPrefix(sql[i:], "/*"):
				state = stateBlockComment
				blockDepth = 1
				i++
			case sql[i] == '\'':
				state = stateSingleQuote
			case sql[i] == '"':
				state = stateDoubleQuote
			case sql[i] == '$':
				if tag, ok := readDollarQuoteTag(sql, i); ok {
					dollarTag = tag
					state = stateDollarQuote
					i += len(tag) - 1
				}
			case sql[i] == ';':
				return hasSQLAfterTerminator(sql[i+1:])
			}
		case stateSingleQuote:
			if sql[i] == '\'' {
				if i+1 < len(sql) && sql[i+1] == '\'' {
					i++
				} else {
					state = stateNormal
				}
			}
		case stateDoubleQuote:
			if sql[i] == '"' {
				if i+1 < len(sql) && sql[i+1] == '"' {
					i++
				} else {
					state = stateNormal
				}
			}
		case stateLineComment:
			if sql[i] == '\n' {
				state = stateNormal
			}
		case stateBlockComment:
			switch {
			case strings.HasPrefix(sql[i:], "/*"):
				blockDepth++
				i++
			case strings.HasPrefix(sql[i:], "*/"):
				blockDepth--
				i++
				if blockDepth == 0 {
					state = stateNormal
				}
			}
		case stateDollarQuote:
			if strings.HasPrefix(sql[i:], dollarTag) {
				i += len(dollarTag) - 1
				state = stateNormal
			}
		}
	}
	return false
}

func hasSQLAfterTerminator(sql string) bool {
	s, ok := stripLeadingSQLComments(sql)
	return !ok || strings.TrimSpace(s) != ""
}

func readDollarQuoteTag(sql string, start int) (string, bool) {
	if start >= len(sql) || sql[start] != '$' {
		return "", false
	}
	for i := start + 1; i < len(sql); i++ {
		switch c := sql[i]; {
		case c == '$':
			return sql[start : i+1], true
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9':
		default:
			return "", false
		}
	}
	return "", false
}
