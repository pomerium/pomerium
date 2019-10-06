package sessions

import "testing"

func Test_ParentSubdomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		s    string
		want string
	}{
		{"httpbin.corp.example.com", "corp.example.com"},
		{"some.httpbin.corp.example.com", "httpbin.corp.example.com"},
		{"example.com", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := ParentSubdomain(tt.s); got != tt.want {
				t.Errorf("ParentSubdomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
