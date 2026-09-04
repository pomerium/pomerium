package idpsession

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestApplySessionClaims(t *testing.T) {
	claims, err := structpb.NewStruct(map[string]any{
		"iss":    "issuer",
		"sub":    "subject",
		"exp":    float64(1234),
		"iat":    float64(1000),
		"email":  "new@example.com",
		"groups": []any{"engineering", "admin"},
	})
	require.NoError(t, err)

	s := &session.Session{Claims: map[string]*structpb.ListValue{
		"preserved": {Values: []*structpb.Value{structpb.NewStringValue("value")}},
		"email":     {Values: []*structpb.Value{structpb.NewStringValue("old@example.com")}},
	}}
	applier := &idpSessionApplier{IDPSession: &idpsession.IDPSession{Claims: claims}}

	applier.ApplyToSession(s)

	assert.Contains(t, s.GetClaims(), "preserved")
	assert.Equal(t, "new@example.com", s.GetClaims()["email"].GetValues()[0].GetStringValue())
	assert.Len(t, s.GetClaims()["groups"].GetValues(), 2)
	assert.NotContains(t, s.GetClaims(), "iss")
	assert.NotContains(t, s.GetClaims(), "sub")
	assert.NotContains(t, s.GetClaims(), "exp")
	assert.NotContains(t, s.GetClaims(), "iat")
}
