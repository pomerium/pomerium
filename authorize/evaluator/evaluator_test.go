package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestJSONMarshal(t *testing.T) {
	dbd := DataBrokerData{
		"type.googleapis.com/directory.User": map[string]interface{}{
			"user1": &directory.User{
				Id:     "user1",
				Groups: []string{"group1", "group2"},
			},
		},
		"type.googleapis.com/session.Session": map[string]interface{}{},
		"type.googleapis.com/user.User":       map[string]interface{}{},
	}

	bs, _ := json.Marshal(new(Evaluator).newInput(&Request{
		DataBrokerData: dbd,
		HTTP: RequestHTTP{
			Method: "GET",
			URL:    "https://example.com",
			Headers: map[string]string{
				"Accept": "application/json",
			},
			ClientCertificate: "CLIENT_CERTIFICATE",
		},
		Session: RequestSession{
			ID:                "SESSION_ID",
			ImpersonateEmail:  "y@example.com",
			ImpersonateGroups: []string{"group1"},
		},
	}, true))
	assert.JSONEq(t, `{
		"databroker_data": {
		},
		"http": {
			"client_certificate": "CLIENT_CERTIFICATE",
			"headers": {
				"Accept": "application/json"
			},
			"method": "GET",
			"url": "https://example.com"
		},
		"session": {
			"id": "SESSION_ID",
			"impersonate_email": "y@example.com",
			"impersonate_groups": ["group1"]
		},
		"is_valid_client_certificate": true
	}`, string(bs))
}

func TestEvaluator_SignedJWT(t *testing.T) {
	opt := config.NewDefaultOptions()
	opt.AuthenticateURL = mustParseURL("https://authenticate.example.com")
	e, err := New(opt)
	require.NoError(t, err)
	req := &Request{
		HTTP: RequestHTTP{
			Method: http.MethodGet,
			URL:    "https://example.com",
		},
	}
	signedJWT, err := e.SignedJWT(req)
	require.NoError(t, err)
	assert.NotEmpty(t, signedJWT)

	payload, err := e.ParseSignedJWT(signedJWT)
	require.NoError(t, err)
	assert.NotEmpty(t, payload)
}

func TestEvaluator_JWTWithKID(t *testing.T) {
	opt := config.NewDefaultOptions()
	opt.AuthenticateURL = mustParseURL("https://authenticate.example.com")
	opt.SigningKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUpCMFZkbko1VjEvbVlpYUlIWHhnd2Q0Yzd5YWRTeXMxb3Y0bzA1b0F3ekdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFVUc1eENQMEpUVDFINklvbDhqS3VUSVBWTE0wNENnVzlQbEV5cE5SbVdsb29LRVhSOUhUMwpPYnp6aktZaWN6YjArMUt3VjJmTVRFMTh1dy82MXJVQ0JBPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
	e, err := New(opt)
	require.NoError(t, err)
	req := &Request{
		HTTP: RequestHTTP{
			Method: http.MethodGet,
			URL:    "https://example.com",
		},
	}
	signedJWT, err := e.SignedJWT(req)
	require.NoError(t, err)
	assert.NotEmpty(t, signedJWT)

	tok, err := jwt.ParseSigned(signedJWT)
	require.NoError(t, err)
	require.Len(t, tok.Headers, 1)
	assert.Equal(t, "5b419ade1895fec2d2def6cd33b1b9a018df60db231dc5ecb85cbed6d942813c", tok.Headers[0].KeyID)
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}

func BenchmarkEvaluator_Evaluate(b *testing.B) {
	e, err := New(&config.Options{
		AuthenticateURL: mustParseURL("https://authn.example.com"),
	})
	if !assert.NoError(b, err) {
		return
	}

	lastSessionID := ""

	dbd := make(DataBrokerData)
	for i := 0; i < 100; i++ {
		sessionID := uuid.New().String()
		lastSessionID = sessionID
		userID := uuid.New().String()
		data, _ := ptypes.MarshalAny(&session.Session{
			Version: fmt.Sprint(i),
			Id:      sessionID,
			UserId:  userID,
			IdToken: &session.IDToken{
				Issuer:   "benchmark",
				Subject:  userID,
				IssuedAt: ptypes.TimestampNow(),
			},
			OauthToken: &session.OAuthToken{
				AccessToken:  "ACCESS TOKEN",
				TokenType:    "Bearer",
				RefreshToken: "REFRESH TOKEN",
			},
		})
		dbd.Update(&databroker.Record{
			Version: fmt.Sprint(i),
			Type:    "type.googleapis.com/session.Session",
			Id:      sessionID,
			Data:    data,
		})
		data, _ = ptypes.MarshalAny(&user.User{
			Version: fmt.Sprint(i),
			Id:      userID,
		})
		dbd.Update(&databroker.Record{
			Version: fmt.Sprint(i),
			Type:    "type.googleapis.com/user.User",
			Id:      userID,
			Data:    data,
		})
	}

	b.ResetTimer()
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		e.Evaluate(ctx, &Request{
			DataBrokerData: dbd,
			HTTP: RequestHTTP{
				Method:  "GET",
				URL:     "https://example.com/path",
				Headers: map[string]string{},
			},
			Session: RequestSession{
				ID: lastSessionID,
			},
		})
	}
}
