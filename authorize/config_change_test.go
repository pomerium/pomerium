package authorize_test

import (
	"context"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/ssh"
)

// trackingPolicyIndexer is a PolicyIndexer that records ProcessConfigUpdate calls.
type trackingPolicyIndexer struct {
	configUpdates chan *config.Config
}

func (t *trackingPolicyIndexer) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (t *trackingPolicyIndexer) ProcessConfigUpdate(cfg *config.Config) {
	select {
	case t.configUpdates <- cfg:
	default:
	}
}

func (t *trackingPolicyIndexer) OnStreamAuthenticated(_ uint64, _ ssh.AuthRequest) {}
func (t *trackingPolicyIndexer) OnSessionCreated(_ *session.Session)               {}
func (t *trackingPolicyIndexer) OnSessionDeleted(_ string)                         {}
func (t *trackingPolicyIndexer) AddStream(_ uint64, _ ssh.PolicyIndexSubscriber)   {}
func (t *trackingPolicyIndexer) RemoveStream(_ uint64)                             {}

// Ensure trackingPolicyIndexer implements ssh.PolicyIndexer.
var _ ssh.PolicyIndexer = (*trackingPolicyIndexer)(nil)

// TestOnConfigChangeReachesPolicyIndexer verifies that when OnConfigChange is
// called with a config that changes the outbound gRPC connection options, the
// policy indexer's ProcessConfigUpdate is still called. This is a regression
// test for a deadlock in CachedOutboundGRPClientConn.Get() where calling
// Get() a second time with the same live context but different options would
// block forever, preventing a.ssh.OnConfigChange(cfg) from executing.
func TestOnConfigChangeReachesPolicyIndexer(t *testing.T) {
	t.Parallel()

	tracker := &trackingPolicyIndexer{
		configUpdates: make(chan *config.Config, 10),
	}

	testPolicy := config.Policy{
		From:         "https://pomerium.io",
		To:           config.WeightedURLs{{URL: url.URL{Scheme: "http", Host: "httpbin.org"}}},
		AllowedUsers: []string{"test@gmail.com"},
	}
	require.NoError(t, testPolicy.Validate())

	opts := &config.Options{
		AuthenticateURLString: "https://authN.example.com",
		DataBroker:            config.DataBrokerOptions{ServiceURL: "https://databroker.example.com"},
		CookieSecret:          "15WXae6fvK9Hal0RGZ600JlCaflYHtNy9bAyOLTlvmc=",
		SharedKey:             "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=",
		Policies:              []config.Policy{testPolicy},
	}

	cfg1 := &config.Config{Options: opts}
	a, err := authorize.New(t.Context(), cfg1,
		authorize.WithPolicyIndexer(func(_ ssh.SSHEvaluator) ssh.PolicyIndexer {
			return tracker
		}),
	)
	require.NoError(t, err)
	require.NotNil(t, a)

	// Drain the initial ProcessConfigUpdate from New().
	select {
	case <-tracker.configUpdates:
	case <-time.After(time.Second):
	}

	// Change InstallationID to trigger different OutboundOptions in
	// CachedOutboundGRPClientConn.Get(). With the deadlock bug, Get() blocks
	// forever and OnConfigChange never reaches ssh.OnConfigChange → ProcessConfigUpdate.
	opts2 := *opts
	opts2.InstallationID = "changed-installation-id"
	cfg2 := &config.Config{Options: &opts2}

	var completed atomic.Bool
	go func() {
		a.OnConfigChange(t.Context(), cfg2)
		completed.Store(true)
	}()

	select {
	case <-tracker.configUpdates:
		// ProcessConfigUpdate was called — no deadlock.
	case <-time.After(5 * time.Second):
		if !completed.Load() {
			t.Fatal("deadlock: authorize.OnConfigChange blocked for 5s in " +
				"CachedOutboundGRPClientConn.Get(); ProcessConfigUpdate was never called")
		}
		t.Fatal("OnConfigChange completed but ProcessConfigUpdate was not called")
	}
}
