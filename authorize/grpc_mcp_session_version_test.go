package authorize

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

// versionGatedQuerier models a synced-data cache that lags a write: it returns
// the record only when the caller demands a minimum record version it can
// satisfy. Below that version (or with no hint) it returns an empty result,
// exactly like a sync querier that hasn't caught up yet.
type versionGatedQuerier struct {
	storage.Querier
	rec          *databroker.Record
	availableAtV uint64
	lastHint     *uint64
}

func (q *versionGatedQuerier) Query(_ context.Context, req *databroker.QueryRequest, _ ...grpc.CallOption) (*databroker.QueryResponse, error) {
	q.lastHint = req.MinimumRecordVersionHint
	if req.MinimumRecordVersionHint == nil || *req.MinimumRecordVersionHint < q.availableAtV {
		return &databroker.QueryResponse{}, nil
	}
	return &databroker.QueryResponse{
		Records:       []*databroker.Record{q.rec},
		RecordVersion: q.rec.Version,
	}, nil
}

func bearerReq(token string) *http.Request {
	hreq := &http.Request{Header: http.Header{}, URL: &url.URL{Path: "/"}}
	hreq.Header.Set("Authorization", "Bearer "+token)
	return hreq
}

// TestGetMCPSession_VersionHintForcesAuthoritativeRead verifies that the access
// token's carried session record version is replayed as a minimum-version hint
// on read. With the hint, a lagging cache is bypassed (the record is observed);
// without it, the same lagging cache reports the session as missing.
func TestGetMCPSession_VersionHintForcesAuthoritativeRead(t *testing.T) {
	t.Parallel()

	const sessionID = "MCP-SESSION-1"
	const version = uint64(42)

	cfg := config.New(config.NewDefaultOptions())
	cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
	a, err := New(t.Context(), cfg)
	require.NoError(t, err)
	h := a.state.Load().mcp

	data := protoutil.NewAny(&session.Session{Id: sessionID, UserId: "USER-1"})
	gated := &versionGatedQuerier{
		rec:          &databroker.Record{Type: data.GetTypeUrl(), Id: sessionID, Data: data, Version: version},
		availableAtV: version,
	}
	ctx := storage.WithQuerier(t.Context(), gated)

	// Token without the version hint (version 0): the lagging cache reports the
	// session as missing — the original bug.
	tokenNoVersion, err := h.GetAccessTokenForSession(sessionID, time.Now().Add(time.Hour))
	require.NoError(t, err)
	_, err = a.getMCPSession(ctx, bearerReq(tokenNoVersion))
	require.Error(t, err, "without a version hint the lagging cache should report the session as not found")

	// Token carrying the issuance version: getMCPSession replays it as the
	// minimum-version hint, so the read observes the session.
	tokenWithVersion, err := h.GetAccessTokenForSessionWithVersion(sessionID, version, time.Now().Add(time.Hour))
	require.NoError(t, err)
	s, err := a.getMCPSession(ctx, bearerReq(tokenWithVersion))
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.Equal(t, sessionID, s.Id)
	require.NotNil(t, gated.lastHint, "the read must carry a minimum-version hint")
	assert.Equal(t, version, *gated.lastHint)
}
