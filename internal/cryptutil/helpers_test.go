package cryptutil // import "github.com/pomerium/pomerium/internal/cryptutil"

import (
	"encoding/base64"
	"testing"
)

func TestGenerateRandomString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		c    int
		want int
	}{
		{"simple", 32, 32},
		{"zero", 0, 0},
		{"negative", -1, 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := NewRandomStringN(tt.c)
			b, err := base64.StdEncoding.DecodeString(o)
			if err != nil {
				t.Error(err)
			}
			got := len(b)
			if got != tt.want {
				t.Errorf("NewRandomStringN() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNewBase64Key(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want int
	}{
		{"simple", 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := NewBase64Key()
			b, err := base64.StdEncoding.DecodeString(o)
			if err != nil {
				t.Error(err)
			}
			got := len(b)
			if got != tt.want {
				t.Errorf("NewBase64Key() = %d, want %d", got, tt.want)
			}
		})
	}
}
