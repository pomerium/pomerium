package authorize

import (
	"testing"
)

func Test_getFullURL(t *testing.T) {
	tests := []struct {
		rawurl, host, expect string
	}{
		{"https://www.example.com/admin", "", "https://www.example.com/admin"},
		{"https://www.example.com/admin", "example.com", "https://www.example.com/admin"},
		{"/admin", "example.com", "http://example.com/admin"},
	}
	for _, tt := range tests {
		actual := getFullURL(tt.rawurl, tt.host)
		if actual != tt.expect {
			t.Errorf("expected getFullURL(%s, %s) to be %s, but got %s", tt.rawurl, tt.host, tt.expect, actual)
		}
	}
}
