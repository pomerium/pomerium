package session_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestHandle(t *testing.T) {
	t.Parallel()

	var h session.Handle
	assert.NoError(t, json.Unmarshal(json.RawMessage(`{
		"jti": "ID",
		"sub": "USER_ID",
		"idp_id": "IDENTITY_PROVIDER_ID",
		"databroker_server_version": 1001,
		"databroker_record_version": 10001,
		"iss": "ISSUER",
		"aud": ["AUDIENCE1","AUDIENCE2"],
		"exp": 1500000000,
		"nbf": 1600000000,
		"iat": 1700000000
	}`), &h))
	assert.Empty(t, cmp.Diff(&session.Handle{
		Id:                      "ID",
		UserId:                  "USER_ID",
		IdentityProviderId:      "IDENTITY_PROVIDER_ID",
		DatabrokerServerVersion: proto.Uint64(1001),
		DatabrokerRecordVersion: proto.Uint64(10001),
		Iss:                     proto.String("ISSUER"),
		Aud:                     []string{"AUDIENCE1", "AUDIENCE2"},
		Exp:                     timestamppb.New(time.Unix(1500000000, 0)),
		Nbf:                     timestamppb.New(time.Unix(1600000000, 0)),
		Iat:                     timestamppb.New(time.Unix(1700000000, 0)),
	}, &h, protocmp.Transform()))

	assert.NoError(t, json.Unmarshal(json.RawMessage(`{
		"sub": "USER_ID1",
		"oid": "USER_ID2"
	}`), &h))
	assert.Equal(t, "USER_ID2", h.UserId)

	bs, err := json.Marshal(&h)
	assert.NoError(t, err)
	assert.JSONEq(t, `{
		"jti": "ID",
		"sub": "USER_ID2",
		"idp_id": "IDENTITY_PROVIDER_ID",
		"databroker_server_version": 1001,
		"databroker_record_version": 10001,
		"iss": "ISSUER",
		"aud": ["AUDIENCE1","AUDIENCE2"],
		"exp": 1500000000,
		"nbf": 1600000000,
		"iat": 1700000000
	}`, string(bs))
}
