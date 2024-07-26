package authenticateflow

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/testutil"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestPopulateSessionFromProfile(t *testing.T) {
	sessionState := &sessions.State{
		Subject: "user-id",
	}
	idToken := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{
		"iss": "https://issuer.example.com",
		"sub": "id-token-user-id",
		"iat": 1721965070,
		"exp": 1721965670
	}`)) + ".fake-signature"
	profile := &identitypb.Profile{
		IdToken: []byte(idToken),
		OauthToken: []byte(`{
			"access_token": "access-token",
			"refresh_token": "refresh-token",
			"expiry": "2024-07-26T12:00:00Z"
		}`),
		Claims: &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"name":  structpb.NewStringValue("John Doe"),
				"email": structpb.NewStringValue("john.doe@example.com"),
			},
		},
	}

	var s session.Session
	populateSessionFromProfile(&s, profile, sessionState, 4*time.Hour)

	assert.Equal(t, 4*time.Hour, s.ExpiresAt.AsTime().Sub(s.IssuedAt.AsTime()))
	assert.Equal(t, s.IssuedAt, s.AccessedAt)
	assert.Equal(t, "user-id", s.UserId)
	testutil.AssertProtoEqual(t, &session.IDToken{
		Issuer:    "https://issuer.example.com",
		Subject:   "id-token-user-id",
		IssuedAt:  &timestamppb.Timestamp{Seconds: 1721965070},
		ExpiresAt: &timestamppb.Timestamp{Seconds: 1721965670},
		Raw:       idToken,
	}, s.IdToken)
	testutil.AssertProtoEqual(t, &session.OAuthToken{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    &timestamppb.Timestamp{Seconds: 1721995200},
	}, s.OauthToken)
	assert.Equal(t, map[string]*structpb.ListValue{
		"name":  {Values: []*structpb.Value{structpb.NewStringValue("John Doe")}},
		"email": {Values: []*structpb.Value{structpb.NewStringValue("john.doe@example.com")}},
	}, s.Claims)
}
