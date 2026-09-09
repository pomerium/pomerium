package idpsession

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestBindingCmpComparesEmbeddedMessages(t *testing.T) {
	t.Parallel()

	r1 := databroker.NewRecord(&user.User{Id: "u1", Claims: map[string]*structpb.ListValue{
		"email":  {Values: []*structpb.Value{structpb.NewStringValue("alice@example.com")}},
		"groups": {Values: []*structpb.Value{structpb.NewStringValue("engineering")}},
	}})
	r2 := databroker.NewRecord(&user.User{Id: "u1", Claims: map[string]*structpb.ListValue{
		"groups": {Values: []*structpb.Value{structpb.NewStringValue("engineering")}},
		"email":  {Values: []*structpb.Value{structpb.NewStringValue("alice@example.com")}},
	}})

	assert.True(t, bindingCmp(r1, r2))

	r2 = databroker.NewRecord(&user.User{Id: "u1", Claims: map[string]*structpb.ListValue{
		"email": {Values: []*structpb.Value{structpb.NewStringValue("bob@example.com")}},
	}})
	assert.False(t, bindingCmp(r1, r2))
}

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
