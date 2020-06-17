package evaluator

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

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
