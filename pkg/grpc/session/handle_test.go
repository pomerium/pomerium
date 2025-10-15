package session_test

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestHandleJSON(t *testing.T) {
	t.Parallel()

	h1 := &session.Handle{
		Id:                      "ID",
		Audience:                []string{"AUDIENCE1", "AUDIENCE2"},
		IdentityProviderId:      proto.String("IDENTITY_PROVIDER_ID"),
		UserId:                  proto.String("USER_ID"),
		DataBrokerServerVersion: proto.Uint64(math.MaxUint64),
		DataBrokerRecordVersion: proto.Uint64(math.MaxUint64 - 1),
	}
	bs, err := json.MarshalIndent(h1, "	", "	")
	assert.NoError(t, err)
	assert.Equal(t, `{
		"sub": "USER_ID",
		"aud": [
			"AUDIENCE1",
			"AUDIENCE2"
		],
		"jti": "ID",
		"idp_id": "IDENTITY_PROVIDER_ID",
		"databroker_server_version": 18446744073709551615,
		"databroker_record_version": 18446744073709551614
	}`, string(bs))

	h2 := new(session.Handle)
	err = json.Unmarshal(bs, &h2)
	assert.NoError(t, err)

	assert.Empty(t, cmp.Diff(h1, h2, protocmp.Transform()))

	t.Run("string audience", func(t *testing.T) {
		t.Parallel()

		h1 := &session.Handle{Audience: []string{"AUDIENCE"}}
		h2 := &session.Handle{}
		err = json.Unmarshal([]byte(`{"aud":"AUDIENCE"}`), h2)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(h1, h2, protocmp.Transform()))
	})
}
