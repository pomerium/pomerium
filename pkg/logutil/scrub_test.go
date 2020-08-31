package logutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestScrubber(t *testing.T) {
	s := NewScrubber("pomerium").Whitelist("user.User", "version", "id")
	c1, _ := anypb.New(wrapperspb.String("claim1"))
	u := s.ScrubProto(&user.User{
		Version: "v1",
		Id:      "u1",
		Name:    "name1",
		Email:   "user@example.com",
		Claims: map[string]*anypb.Any{
			"key1": c1,
		},
	}).(*user.User)

	assert.Equal(t, "v1", u.Version)
	assert.Equal(t, "u1", u.Id)
	assert.Equal(t, s.hmacString("name1"), u.Name)
	assert.Equal(t, s.hmacString("user@example.com"), u.Email)
	assert.Equal(t, s.hmacString("claim1"), u.GetClaim("key1"))
}
