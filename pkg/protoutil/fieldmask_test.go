package protoutil_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestOverwriteMasked(t *testing.T) {
	t.Parallel()

	s1 := &session.Session{
		Id:       "session-id",
		IssuedAt: timestamppb.New(time.Date(2023, 10, 25, 10, 0, 0, 0, time.UTC)),
	}
	s2 := &session.Session{
		Id:         "new-session-id",
		AccessedAt: timestamppb.New(time.Date(2023, 10, 25, 12, 0, 0, 0, time.UTC)),
		OauthToken: &session.OAuthToken{
			AccessToken: "new-access-token",
			TokenType:   "bearer",
		},
	}

	m, err := fieldmaskpb.New(s2,
		"issued_at", "accessed_at", "oauth_token.access_token", "id_token.raw")
	require.NoError(t, err)

	err = protoutil.OverwriteMasked(s1, s2, m)
	require.NoError(t, err)

	testutil.AssertProtoJSONEqual(t, `{
		"id": "session-id",
		"accessedAt": "2023-10-25T12:00:00Z",
		"oauthToken": {
			"accessToken": "new-access-token"
		}
	}`, s1)
}

func TestOverwriteMaskedErrors(t *testing.T) {
	t.Parallel()

	var s1, s2 session.Session
	var o session.OAuthToken

	err := protoutil.OverwriteMasked(&s1, &s2, &fieldmaskpb.FieldMask{Paths: []string{"foo"}})
	assert.Equal(t, `cannot overwrite unknown field "foo" in message session.Session`, err.Error())

	err = protoutil.OverwriteMasked(&s1, &s2,
		&fieldmaskpb.FieldMask{Paths: []string{"device_credentials.type_id"}})
	assert.Equal(t, `cannot overwrite sub-fields of field "device_credentials" in message `+
		"session.Session", err.Error())

	m, _ := fieldmaskpb.New(&s1, "expires_at")
	err = protoutil.OverwriteMasked(&s1, &o, m)
	assert.Equal(t, "descriptor mismatch: session.Session, session.OAuthToken", err.Error())
}
