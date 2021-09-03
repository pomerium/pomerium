package manager

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/directory"
)

type mockProvider struct {
	user       func(ctx context.Context, userID, accessToken string) (*directory.User, error)
	userGroups func(ctx context.Context) ([]*directory.Group, []*directory.User, error)
}

func (mock mockProvider) User(ctx context.Context, userID, accessToken string) (*directory.User, error) {
	return mock.user(ctx, userID, accessToken)
}

func (mock mockProvider) UserGroups(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
	return mock.userGroups(ctx)
}

func TestManager_refreshDirectoryUserGroups(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	t.Run("backoff", func(t *testing.T) {
		cnt := 0
		mgr := New(
			WithDirectoryProvider(mockProvider{
				userGroups: func(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
					cnt++
					switch cnt {
					case 1:
						return nil, nil, fmt.Errorf("error 1")
					case 2:
						return nil, nil, fmt.Errorf("error 2")
					}
					return nil, nil, nil
				},
			}),
			WithGroupRefreshInterval(time.Hour),
		)
		dur1 := mgr.refreshDirectoryUserGroups(ctx)
		dur2 := mgr.refreshDirectoryUserGroups(ctx)
		dur3 := mgr.refreshDirectoryUserGroups(ctx)

		assert.Greater(t, dur2, dur1)
		assert.Greater(t, dur3, dur2)
		assert.Equal(t, time.Hour, dur3)
	})
}
