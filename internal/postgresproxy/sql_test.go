package postgresproxy

import (
	"strings"
	"testing"
)

func TestHasMultipleStatements(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want bool
	}{
		{name: "single statement", sql: "select 1", want: false},
		{name: "trailing semicolon", sql: "select 1;", want: false},
		{name: "trailing semicolon line comment", sql: "select 1; -- trailing comment", want: false},
		{name: "trailing semicolon block comment", sql: "select 1; /* trailing comment */", want: false},
		{name: "two statements", sql: "select 1; select 2", want: true},
		{name: "single quoted semicolon", sql: "select ';'", want: false},
		{name: "double quoted semicolon", sql: `select ";" from example`, want: false},
		{name: "line comment semicolon", sql: "select 1 -- ;\n", want: false},
		{name: "block comment semicolon", sql: "select /* ; */ 1", want: false},
		{name: "dollar quoted semicolon", sql: "select $$;$$", want: false},
		{name: "statement after dollar quote", sql: "select $$;$$; drop table x", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasMultipleStatements(tt.sql); got != tt.want {
				t.Fatalf("hasMultipleStatements(%q) = %t, want %t", tt.sql, got, tt.want)
			}
		})
	}
}

func TestClassifySQL(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want string
	}{
		{name: "leading comments", sql: "-- comment\n/* block */ select 1", want: "SELECT"},
		{name: "nested block comment before drop", sql: "/*/* */ SELECT */ DROP TABLE users", want: "DROP"},
		{name: "parenthesized select", sql: "(select 1)", want: "SELECT"},
		{name: "select function call", sql: "select(1)", want: "SELECT"},
		{name: "select with block comment", sql: "select/*comment*/1", want: "SELECT"},
		{name: "select into", sql: "select 1 into blocked_target", want: "SELECT_INTO"},
		{name: "long select into", sql: longSelectIntoSQL(), want: "SELECT_INTO"},
		{name: "select for update", sql: "select * from example for update", want: "SELECT_FOR_LOCK"},
		{name: "long select for update", sql: longSelectForUpdateSQL(), want: "SELECT_FOR_LOCK"},
		{name: "set role", sql: "set role administrator", want: "SET_ROLE"},
		{name: "set role equals", sql: "set role = 'administrator'", want: "SET_ROLE"},
		{name: "set local role", sql: "set local role administrator", want: "SET_ROLE"},
		{name: "set session role", sql: "set session role administrator", want: "SET_ROLE"},
		{name: "set session authorization", sql: "set session authorization administrator", want: "SET_SESSION_AUTHORIZATION"},
		{name: "set local session authorization", sql: "set local session authorization administrator", want: "SET_SESSION_AUTHORIZATION"},
		{name: "set session_authorization", sql: "set session_authorization = 'administrator'", want: "SET_SESSION_AUTHORIZATION"},
		{name: "set local session_authorization", sql: "set local session_authorization to 'administrator'", want: "SET_SESSION_AUTHORIZATION"},
		{name: "reset role", sql: "reset role", want: "RESET_ROLE"},
		{name: "reset session authorization", sql: "reset session authorization", want: "RESET_SESSION_AUTHORIZATION"},
		{name: "reset all", sql: "reset all", want: "RESET_ALL"},
		{name: "unterminated leading block comment", sql: "/* unfinished", want: "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifySQL(tt.sql); got != tt.want {
				t.Fatalf("classifySQL(%q) = %q, want %q", tt.sql, got, tt.want)
			}
		})
	}
}

func TestIdentityChangingStatementsRequireParserSupport(t *testing.T) {
	for _, sql := range []string{
		"set role administrator",
		"set role = 'administrator'",
		"set local role administrator",
		"set session role administrator",
		"set session authorization administrator",
		"set local session authorization administrator",
		"set session_authorization = 'administrator'",
		"set local session_authorization to 'administrator'",
		"reset role",
		"reset session authorization",
		"reset all",
	} {
		t.Run(sql, func(t *testing.T) {
			if class := classifySQL(sql); !requiresParserSupport(class) {
				t.Fatalf("classifySQL(%q) = %q, which does not require parser support", sql, class)
			}
		})
	}
}

func longSelectIntoSQL() string {
	return "select " + strings.Join(longSelectExpressions(), ", ") + " into blocked_target"
}

func longSelectForUpdateSQL() string {
	return "select " + strings.Join(longSelectExpressions(), ", ") + " from sensitive_rows for update"
}

func longSelectExpressions() []string {
	return []string{
		"1 as c1", "2 as c2", "3 as c3", "4 as c4", "5 as c5",
		"6 as c6", "7 as c7", "8 as c8", "9 as c9", "10 as c10",
		"11 as c11", "12 as c12", "13 as c13", "14 as c14", "15 as c15",
		"16 as c16", "17 as c17", "18 as c18", "19 as c19", "20 as c20",
	}
}
