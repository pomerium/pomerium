package identity_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/grpc/identity"
)

func TestHash(t *testing.T) {
	t.Parallel()

	p1 := &identity.Provider{Id: "id1"}
	p2 := &identity.Provider{Id: "id2"}

	assert.Equal(t, p1.Hash(), p2.Hash(), "should ignore ids for hash")
}
