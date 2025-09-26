package handlers_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
)

func TestUserInfoData(t *testing.T) {
	t.Parallel()

	claims, _ := structpb.NewStruct(map[string]any{
		"TEST": "VALUE",
	})
	data := handlers.UserInfoData{Profile: &identity.Profile{Claims: claims}}
	m := data.ToJSON()
	bs, err := json.Marshal(m)
	assert.NoError(t, err)
	assert.JSONEq(t, `{
		"isEnterprise": false,
		"isImpersonated": false,
		"profile": {
			"claims": {"TEST":"VALUE"}
		},
		"session": null,
		"user": null,
		"webAuthnCreationOptions": null,
		"webAuthnRequestOptions": null,
		"webAuthnUrl": ""
	}`, string(bs))
}
