package authorize

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/storage"
)

// newMCPAuthorize builds an Authorize with the MCP runtime flag enabled and the
// given databroker client wired into its state, plus a Bearer-token request for
// sessionID signed with the handler's cipher.
func newMCPAuthorize(t *testing.T, client databroker.DataBrokerServiceClient, sessionID string) (*Authorize, *http.Request) {
	t.Helper()

	cfg := config.New(config.NewDefaultOptions())
	cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
	a, err := New(t.Context(), cfg)
	require.NoError(t, err)

	state := *a.state.Load()
	state.dataBrokerClient = client
	a.state.Store(&state)

	accessToken, err := state.mcp.GetAccessTokenForSession(sessionID, time.Now().Add(time.Hour))
	require.NoError(t, err)

	hreq := &http.Request{Header: http.Header{}, URL: &url.URL{Path: "/"}}
	hreq.Header.Set("Authorization", "Bearer "+accessToken)
	return a, hreq
}

// TestGetMCPSession_AuthoritativeRead guards against a read-after-write race in
// MCP session resolution.
//
// The MCP token endpoint creates a session in the databroker and immediately
// returns an access token referencing it; the very next request must be able to
// observe that session. If session lookup is served from the eventually
// consistent synced-data cache, a not-yet-synced session reads as "not found"
// and the request is denied with a 401 — a window the clustered (raft)
// databroker widens substantially. MCP session reads must therefore go to the
// databroker authoritatively.
//
// The test simulates the lagging cache by placing an empty (but non-erroring)
// querier in the request context while the databroker holds the session.
func TestGetMCPSession_AuthoritativeRead(t *testing.T) {
	t.Parallel()

	const sessionID = "MCP-SESSION-1"

	db := testutil.NewTestDatabroker(t)
	putRecords(t, db, &session.Session{Id: sessionID, UserId: "USER-1"})

	a, hreq := newMCPAuthorize(t, db, sessionID)

	// Synced-data cache that is ready but lags the write: it returns zero records
	// without an error, so a cache-based read reports "not found".
	ctx := storage.WithQuerier(t.Context(), storage.NewStaticQuerier())

	s, err := a.getMCPSession(ctx, hreq)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.Equal(t, sessionID, s.Id)
}

// errDataBrokerClient returns a fixed error from Get and delegates everything
// else to the embedded client.
type errDataBrokerClient struct {
	databroker.DataBrokerServiceClient
	err error
}

func (c errDataBrokerClient) Get(context.Context, *databroker.GetRequest, ...grpc.CallOption) (*databroker.GetResponse, error) {
	return nil, c.err
}

// TestGetMCPSession_TransientErrorIsNotMissingSession ensures a transient
// databroker error is not reported as a missing session.
//
// A codes.Unavailable error — e.g. a raft leader election in progress — must be
// surfaced as a temporary/retryable error, not collapsed into
// sessions.ErrNoSessionFound. Otherwise loadSession treats a valid token as
// having no session and denies the request with a 401, pushing MCP clients into
// a re-authentication loop. This mirrors the cookie-session path, which
// preserves codes.Unavailable.
func TestGetMCPSession_TransientErrorIsNotMissingSession(t *testing.T) {
	t.Parallel()

	client := errDataBrokerClient{
		DataBrokerServiceClient: testutil.NewTestDatabroker(t),
		err:                     status.Error(codes.Unavailable, "cluster has no leader"),
	}
	a, hreq := newMCPAuthorize(t, client, "MCP-SESSION-1")

	_, err := a.getMCPSession(t.Context(), hreq)
	require.Error(t, err)
	assert.False(t, errors.Is(err, sessions.ErrNoSessionFound),
		"a transient databroker error must not be collapsed into ErrNoSessionFound (would yield a 401 instead of a retry)")
	assert.Equal(t, codes.Unavailable, status.Code(err),
		"the Unavailable status code must be preserved so it can be treated as temporary")
}
