package token_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/zero/token"
)

func TestCache(t *testing.T) {
	t.Parallel()

	t.Run("token expired, fetch new", func(t *testing.T) {
		t.Parallel()

		var testToken *token.Token
		var testError error
		fetcher := func(_ context.Context, _ string) (*token.Token, error) {
			if testToken != nil {
				token := *testToken
				return &token, nil
			}
			return nil, testError
		}

		c := token.NewCache(fetcher, "test-refresh-token")
		now := time.Now()
		c.TimeNow = func() time.Time { return now }

		testToken = &token.Token{"bearer-1", now.Add(time.Hour)}
		bearer, err := c.GetToken(context.Background(), time.Minute)
		require.NoError(t, err)
		assert.Equal(t, "bearer-1", bearer)

		now = now.Add(time.Minute * 30)
		testToken.Bearer = "bearer-2"

		// token is still valid, so we should get the same one
		bearer, err = c.GetToken(context.Background(), time.Minute*20)
		require.NoError(t, err)
		assert.Equal(t, "bearer-1", bearer)

		now = now.Add(time.Minute * 30)
		testToken = &token.Token{"bearer-3", now.Add(time.Hour)}
		bearer, err = c.GetToken(context.Background(), time.Minute*30)
		require.NoError(t, err)
		assert.Equal(t, "bearer-3", bearer)
	})

	t.Run("reset", func(t *testing.T) {
		t.Parallel()

		var calls int
		fetcher := func(_ context.Context, _ string) (*token.Token, error) {
			calls++
			return &token.Token{fmt.Sprintf("bearer-%d", calls), time.Now().Add(time.Hour)}, nil
		}

		ctx := context.Background()
		c := token.NewCache(fetcher, "test-refresh-token")
		got, err := c.GetToken(ctx, time.Minute*2)
		assert.NoError(t, err)
		assert.Equal(t, "bearer-1", got)

		got, err = c.GetToken(ctx, time.Minute*2)
		assert.NoError(t, err)
		assert.Equal(t, "bearer-1", got)

		c.Reset()
		got, err = c.GetToken(ctx, time.Minute*2)
		assert.NoError(t, err)
		assert.Equal(t, "bearer-2", got)
	})
}
