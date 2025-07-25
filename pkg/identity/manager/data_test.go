package manager

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	go_oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestUser_UnmarshalJSON(t *testing.T) {
	u := new(user.User)
	err := json.Unmarshal([]byte(`{
		"name": "joe",
		"email": "joe@test.com",
		"some-other-claim": "xyz"
	}`), newUserUnmarshaler(u))
	assert.NoError(t, err)
	assert.Equal(t, "joe", u.Name)
	assert.Equal(t, "joe@test.com", u.Email)
	assert.Equal(t, map[string]*structpb.ListValue{
		"some-other-claim": {Values: []*structpb.Value{protoutil.ToStruct("xyz")}},
	}, u.Claims)
}

func TestSession_NextRefresh(t *testing.T) {
	t.Run("refresh at ID token expiration", func(t *testing.T) {
		r := RefreshSessionAtIDTokenExpiration(true)

		tm1 := time.Date(2020, 6, 5, 12, 0, 0, 0, time.UTC)
		s := &session.Session{}
		gracePeriod := time.Second * 10
		coolOffDuration := time.Minute
		assert.Equal(t, tm1.Add(time.Minute), nextSessionRefresh(s, tm1, gracePeriod, coolOffDuration, r))

		tm2 := time.Date(2020, 6, 5, 13, 0, 0, 0, time.UTC)
		s.OauthToken = &session.OAuthToken{
			ExpiresAt: timestamppb.New(tm2),
		}
		assert.Equal(t, tm2.Add(-time.Second*10), nextSessionRefresh(s, tm1, gracePeriod, coolOffDuration, r))

		tm3 := time.Date(2020, 6, 5, 12, 30, 0, 0, time.UTC)
		s.IdToken = &session.IDToken{
			ExpiresAt: timestamppb.New(tm3),
		}
		assert.Equal(t, tm3.Add(-time.Second*10), nextSessionRefresh(s, tm1, gracePeriod, coolOffDuration, r))

		tm4 := time.Date(2020, 6, 5, 12, 15, 0, 0, time.UTC)
		s.ExpiresAt = timestamppb.New(tm4)
		assert.Equal(t, tm4, nextSessionRefresh(s, tm1, gracePeriod, coolOffDuration, r))
	})
	t.Run("do not refresh at ID token expiration", func(t *testing.T) {
		r := RefreshSessionAtIDTokenExpiration(false)

		tm1 := time.Date(2020, 6, 5, 12, 0, 0, 0, time.UTC)
		s := &session.Session{}
		gracePeriod := time.Second * 10
		coolOffDuration := time.Minute
		assert.Equal(t, tm1.Add(time.Minute), nextSessionRefresh(s, tm1, gracePeriod, coolOffDuration, r))

		tm2 := time.Date(2020, 6, 5, 13, 0, 0, 0, time.UTC)
		s.OauthToken = &session.OAuthToken{
			ExpiresAt: timestamppb.New(tm2),
		}
		assert.Equal(t, tm2.Add(-time.Second*10), nextSessionRefresh(s, tm1, gracePeriod, coolOffDuration, r))

		tm3 := time.Date(2020, 6, 5, 12, 30, 0, 0, time.UTC)
		s.IdToken = &session.IDToken{
			ExpiresAt: timestamppb.New(tm3),
		}
		assert.Equal(t, tm2.Add(-time.Second*10), nextSessionRefresh(s, tm1, gracePeriod, coolOffDuration, r))

		tm4 := time.Date(2020, 6, 5, 12, 15, 0, 0, time.UTC)
		s.ExpiresAt = timestamppb.New(tm4)
		assert.Equal(t, tm4, nextSessionRefresh(s, tm1, gracePeriod, coolOffDuration, r))
	})
}

func TestSession_UnmarshalJSON(t *testing.T) {
	tm := time.Date(2020, 6, 5, 12, 0, 0, 0, time.UTC)
	s := new(session.Session)
	err := json.Unmarshal([]byte(`{
		"iss": "https://some.issuer.com",
		"sub": "subject",
		"exp": `+fmt.Sprint(tm.Unix())+`,
		"iat": `+fmt.Sprint(tm.Unix())+`,
		"some-other-claim": "xyz"
	}`), newSessionUnmarshaler(s))
	assert.NoError(t, err)
	assert.Equal(t, map[string]*structpb.ListValue{
		"some-other-claim": {Values: []*structpb.Value{protoutil.ToStruct("xyz")}},
	}, s.Claims)
}

// Simulate the behavior during an oidc.Authenticator Refresh() call:
// SetRawIDToken() followed by a Claims() unmarshal call.
func TestSession_RefreshUpdate(t *testing.T) {
	// Create a valid go_oidc.IDToken. This requires a real signing key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iat := time.Now().Unix()
	exp := iat + 3600
	payload := map[string]any{
		"iss":              "https://issuer.example.com",
		"aud":              "https://client.example.com",
		"sub":              "subject",
		"exp":              exp,
		"iat":              iat,
		"some-other-claim": "xyz",
	}
	jwtSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	require.NoError(t, err)
	rawIDToken, err := jwt.Signed(jwtSigner).Claims(payload).CompactSerialize()
	require.NoError(t, err)

	keySet := &go_oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{privateKey.Public()}}
	verifier := go_oidc.NewVerifier("https://issuer.example.com", keySet, &go_oidc.Config{
		ClientID: "https://client.example.com",
	})

	// Finally, we can obtain a go_oidc.IDToken.
	idToken, err := verifier.Verify(t.Context(), rawIDToken)
	require.NoError(t, err)

	// This is the behavior under test.
	var s session.Session
	v := newSessionUnmarshaler(&s)
	v.SetRawIDToken(rawIDToken)
	err = idToken.Claims(v)

	assert.NoError(t, err)
	assert.NotNil(t, s.IdToken)
	assert.Equal(t, "https://issuer.example.com", s.IdToken.Issuer)
	assert.Equal(t, "subject", s.IdToken.Subject)
	assert.Equal(t, &timestamppb.Timestamp{Seconds: exp}, s.IdToken.ExpiresAt)
	assert.Equal(t, &timestamppb.Timestamp{Seconds: iat}, s.IdToken.IssuedAt)
	assert.Equal(t, map[string]*structpb.ListValue{
		"aud": {
			Values: []*structpb.Value{structpb.NewStringValue("https://client.example.com")},
		},
		"some-other-claim": {
			Values: []*structpb.Value{structpb.NewStringValue("xyz")},
		},
	}, s.Claims)
	assert.Equal(t, rawIDToken, s.IdToken.Raw)
}
