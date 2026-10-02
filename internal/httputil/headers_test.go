package httputil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBearerToken(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		authorization string
		token         string
		ok            bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER abc", "abc", true},
		{"Bearer ", "", true},
		{"Bearer", "", false},
		{"Basic abc", "", false},
		{"Pomerium abc", "", false},
		{"", "", false},
	} {
		token, ok := BearerToken(tc.authorization)
		assert.Equal(t, tc.ok, ok, tc.authorization)
		assert.Equal(t, tc.token, token, tc.authorization)
	}
}

func TestPomeriumAuthorizationToken(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		authorization string
		token         string
		ok            bool
	}{
		{"Pomerium abc", "abc", true},
		{"pomerium abc", "", false},
		{"Pomerium-abc", "", false},
		{"Bearer Pomerium-abc", "", false},
		{"", "", false},
	} {
		token, ok := PomeriumAuthorizationToken(tc.authorization)
		assert.Equal(t, tc.ok, ok, tc.authorization)
		assert.Equal(t, tc.token, token, tc.authorization)
	}
}

func TestPomeriumBearerToken(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		authorization string
		token         string
		ok            bool
	}{
		{"Bearer Pomerium-abc", "abc", true},
		{"bearer Pomerium-abc", "abc", true},
		{"Bearer abc", "", false},
		{"Bearer Pomerium abc", "", false},
		{"Pomerium abc", "", false},
		{"", "", false},
	} {
		token, ok := PomeriumBearerToken(tc.authorization)
		assert.Equal(t, tc.ok, ok, tc.authorization)
		assert.Equal(t, tc.token, token, tc.authorization)
	}
}
