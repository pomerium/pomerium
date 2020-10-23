package logutil

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestScrubber(t *testing.T) {
	s := NewScrubber("pomerium").Whitelist("user.User", "version", "id")
	u := s.ScrubProto(&user.User{
		Version: "v1",
		Id:      "u1",
		Name:    "name1",
		Email:   "user@example.com",
	}).(*user.User)

	assert.Equal(t, "v1", u.Version)
	assert.Equal(t, "u1", u.Id)
	assert.Equal(t, s.hmacString("name1"), u.Name)
	assert.Equal(t, s.hmacString("user@example.com"), u.Email)
}
