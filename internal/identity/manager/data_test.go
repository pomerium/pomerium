package manager

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/internal/grpc/session"
)

func TestUser_UnmarshalJSON(t *testing.T) {
	var u User
	err := json.Unmarshal([]byte(`{
		"name": "joe",
		"email": "joe@test.com",
		"some-other-claim": "xyz"
	}`), &u)
	assert.NoError(t, err)
	assert.NotNil(t, u.User)
	assert.Equal(t, "joe", u.User.Name)
	assert.Equal(t, "joe@test.com", u.User.Email)
	anyv, _ := ptypes.MarshalAny(&wrapperspb.StringValue{Value: "xyz"})
	assert.Equal(t, map[string]*anypb.Any{
		"some-other-claim": anyv,
	}, u.Claims)
}

func TestSession_NextRefresh(t *testing.T) {
	tm1 := time.Date(2020, 6, 5, 12, 0, 0, 0, time.UTC)
	s := Session{
		Session:         &session.Session{},
		lastRefresh:     tm1,
		gracePeriod:     time.Second * 10,
		coolOffDuration: time.Minute,
	}
	assert.Equal(t, tm1.Add(time.Minute), s.NextRefresh())

	tm2 := time.Date(2020, 6, 5, 13, 0, 0, 0, time.UTC)
	pbtm2, _ := ptypes.TimestampProto(tm2)
	s.OauthToken = &session.OAuthToken{
		ExpiresAt: pbtm2,
	}
	assert.Equal(t, tm2.Add(-time.Second*10), s.NextRefresh())

	tm3 := time.Date(2020, 6, 5, 12, 30, 0, 0, time.UTC)
	pbtm3, _ := ptypes.TimestampProto(tm3)
	s.IdToken = &session.IDToken{
		ExpiresAt: pbtm3,
	}
	assert.Equal(t, tm3.Add(-time.Second*10), s.NextRefresh())

	tm4 := time.Date(2020, 6, 5, 12, 15, 0, 0, time.UTC)
	pbtm4, _ := ptypes.TimestampProto(tm4)
	s.ExpiresAt = pbtm4
	assert.Equal(t, tm4, s.NextRefresh())
}

func TestSession_UnmarshalJSON(t *testing.T) {
	tm := time.Date(2020, 6, 5, 12, 0, 0, 0, time.UTC)
	pbtm, _ := ptypes.TimestampProto(tm)
	var s Session
	err := json.Unmarshal([]byte(`{
		"iss": "https://some.issuer.com",
		"sub": "subject",
		"exp": `+fmt.Sprint(tm.Unix())+`,
		"iat": `+fmt.Sprint(tm.Unix())+`,
		"some-other-claim": "xyz"
	}`), &s)
	assert.NoError(t, err)
	assert.NotNil(t, s.Session)
	assert.NotNil(t, s.Session.IdToken)
	assert.Equal(t, "https://some.issuer.com", s.Session.IdToken.Issuer)
	assert.Equal(t, "subject", s.Session.IdToken.Subject)
	assert.Equal(t, pbtm, s.Session.IdToken.ExpiresAt)
	assert.Equal(t, pbtm, s.Session.IdToken.IssuedAt)
	anyv, _ := ptypes.MarshalAny(&wrapperspb.StringValue{Value: "xyz"})
	assert.Equal(t, map[string]*anypb.Any{
		"some-other-claim": anyv,
	}, s.Claims)
}
