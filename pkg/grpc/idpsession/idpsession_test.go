package idpsession

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestIDPSessionUnmarshalJSON(t *testing.T) {
	claims, err := structpb.NewStruct(map[string]any{
		"iss":   "login-issuer",
		"sub":   "login-subject",
		"exp":   float64(1234),
		"iat":   float64(1000),
		"email": "old@example.com",
	})
	require.NoError(t, err)
	s := &IDPSession{Claims: claims}

	require.NoError(t, s.UnmarshalJSON([]byte(`{
		"iss": "refresh-issuer",
		"sub": "refresh-subject",
		"exp": 5678,
		"iat": 5000,
		"email": "new@example.com"
	}`)))

	got := s.GetClaims().AsMap()
	assert.Equal(t, "login-issuer", got["iss"])
	assert.Equal(t, "login-subject", got["sub"])
	assert.Equal(t, float64(1234), got["exp"])
	assert.Equal(t, float64(1000), got["iat"])
	assert.Equal(t, []any{"new@example.com"}, got["email"])
}
