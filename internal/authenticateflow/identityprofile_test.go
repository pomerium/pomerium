package authenticateflow

import (
	"encoding/base64"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/testutil"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestPopulateSessionFromProfile(t *testing.T) {
	timeNow = func() time.Time { return time.Unix(1721965100, 0) }
	t.Cleanup(func() { timeNow = time.Now })

	h := &sessions.Handle{
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
	populateSessionFromProfile(&s, profile, h, 4*time.Hour)

	testutil.AssertProtoEqual(t, &session.Session{
		IssuedAt:   timestamppb.New(timeNow()),
		AccessedAt: timestamppb.New(timeNow()),
		ExpiresAt:  timestamppb.New(timeNow().Add(4 * time.Hour)),
		UserId:     "user-id",
		IdToken: &session.IDToken{
			Issuer:    "https://issuer.example.com",
			Subject:   "id-token-user-id",
			IssuedAt:  &timestamppb.Timestamp{Seconds: 1721965070},
			ExpiresAt: &timestamppb.Timestamp{Seconds: 1721965670},
			Raw:       idToken,
		},
		OauthToken: &session.OAuthToken{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresAt:    &timestamppb.Timestamp{Seconds: 1721995200},
		},
		Claims: map[string]*structpb.ListValue{
			"name":  {Values: []*structpb.Value{structpb.NewStringValue("John Doe")}},
			"email": {Values: []*structpb.Value{structpb.NewStringValue("john.doe@example.com")}},
		},
	}, &s)
}
