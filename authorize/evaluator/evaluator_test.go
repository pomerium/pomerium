package evaluator

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/grpc/directory"
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

	bs, _ := json.Marshal(input{
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
		IsValidClientCertificate: true,
	})
	assert.JSONEq(t, `{
		"databroker_data": {
			"type.googleapis.com/directory.User": {
				"user1": {
					"id": "user1",
					"groups": ["group1", "group2"]
				}
			},
			"type.googleapis.com/session.Session": {},
			"type.googleapis.com/user.User": {}
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

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}
