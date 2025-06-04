package authorize

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestAuthorize_getDataBrokerSessionOrServiceAccount(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	t.Cleanup(clearTimeout)

	opt := config.NewDefaultOptions()
	a, err := New(t.Context(), &config.Config{Options: opt})
	require.NoError(t, err)

	s1 := &session.Session{Id: "s1", ExpiresAt: timestamppb.New(time.Now().Add(-time.Second))}
	sq := storage.NewStaticQuerier(s1)
	qctx := storage.WithQuerier(ctx, sq)
	_, err = a.getDataBrokerSessionOrServiceAccount(qctx, "s1", 0)
	assert.ErrorIs(t, err, session.ErrSessionExpired)
}
