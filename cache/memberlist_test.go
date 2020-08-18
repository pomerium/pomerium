package cache

import (
	"context"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestCache_runMemberList(t *testing.T) {
	c, err := New(&config.Config{
		Options: &config.Options{
			SharedKey:     cryptutil.NewBase64Key(),
			DataBrokerURL: &url.URL{Scheme: "http", Host: "member1"},
			Provider:      "google",
		},
	})
	require.NoError(t, err)

	ctx, cancelFunc := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancelFunc()

	ch := make(chan error)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ch <- c.runMemberList(ctx)
		close(ch)
	}()

	select {
	case <-ctx.Done():
		// No error
	case err := <-ch:
		assert.NoError(t, err)
	}

	// When we're here, either there an error, or ch was closed already.
	assert.NoError(t, <-ch)
	wg.Wait()
}
