package handlers_test

import (
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
	assert.Equal(t, false, m["isEnterprise"])
	assert.Equal(t, false, m["isImpersonated"])
	assert.Equal(t, map[string]any{"claims": map[string]any{"TEST": "VALUE"}}, m["profile"])
	assert.Nil(t, m["session"])
	assert.Nil(t, m["user"])
	assert.Nil(t, m["webAuthnCreationOptions"])
	assert.Nil(t, m["webAuthnRequestOptions"])
	assert.Equal(t, "", m["webAuthnUrl"])
}
