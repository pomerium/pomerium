package oauth21_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/oauth21"
)

// TestVerifyPKCES256 tests the S256 PKCE verification method.
func TestVerifyPKCES256(t *testing.T) {
	// Example values from RFC 7636 Appendix B
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	tests := []struct {
		name      string
		verifier  string
		challenge string
		want      bool
	}{
		{
			name:      "Correct Verifier",
			verifier:  verifier,
			challenge: challenge,
			want:      true,
		},
		{
			name:      "Incorrect Verifier",
			verifier:  "incorrect_verifier_string",
			challenge: challenge,
			want:      false,
		},
		{
			name:      "Incorrect Challenge",
			verifier:  verifier,
			challenge: "incorrect_challenge_string",
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := oauth21.VerifyPKCES256(tc.verifier, tc.challenge)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestVerifyPKCEPlain tests the Plain PKCE verification method.
func TestVerifyPKCEPlain(t *testing.T) {
	verifierPlain := "this-is-a-plain-verifier-43-chars-long-askldfj"

	tests := []struct {
		name      string
		verifier  string
		challenge string
		want      bool
	}{
		{
			name:      "Correct Verifier",
			verifier:  verifierPlain,
			challenge: verifierPlain,
			want:      true,
		},
		{
			name:      "Incorrect Verifier",
			verifier:  "incorrect_verifier_string",
			challenge: verifierPlain,
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := oauth21.VerifyPKCEPlain(tc.verifier, tc.challenge)
			assert.Equal(t, tc.want, got)
		})
	}
}
