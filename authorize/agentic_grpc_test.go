package authorize

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/agentic"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// TestResolveBearer covers the credential-dispatch decision: which resolver a
// request uses given the agentic flag, whether the route is MCP-marked, whether
// the Authorization header carries a run token, and the route's
// bearer_token_format. Acceptance of a run token is declared per route, MCP
// routes included: without bearer_token_format: agentic_run_token no route
// interprets one.
func TestResolveBearer(t *testing.T) {
	const (
		agenticFmt = configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_AGENTIC_RUN_TOKEN
		jwtFmt     = configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT
		unknownFmt = configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_UNKNOWN
	)
	cases := []struct {
		name                                  string
		agenticEnabled, isMCPRoute, hasRunTok bool
		format                                configpb.BearerTokenFormat
		want                                  bearerResolution
	}{
		{"mcp route + declared format + run token -> agentic", true, true, true, agenticFmt, resolveAgentic},
		{"mcp route + undeclared format + run token -> mcp", true, true, true, unknownFmt, resolveMCP},
		{"mcp route + non-run bearer -> mcp", true, true, false, agenticFmt, resolveMCP},
		{"mcp route, agentic off, run token -> mcp", false, true, true, agenticFmt, resolveMCP},
		{"declared format + run token -> agentic", true, false, true, agenticFmt, resolveAgentic},
		{"declared format, no run token -> none", true, false, false, agenticFmt, resolveNone},
		{"declared format, agentic off -> none", false, false, true, agenticFmt, resolveNone},
		{"undeclared route + run token -> none", true, false, true, unknownFmt, resolveNone},
		{"jwt route + run token -> none", true, false, true, jwtFmt, resolveNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveBearer(tc.agenticEnabled, tc.isMCPRoute, tc.hasRunTok, tc.format)
			require.Equal(t, tc.want, got)
		})
	}
}

// unavailableDataBroker is a databroker client whose Get always fails with a
// transient codes.Unavailable, simulating a databroker rolling restart / blip.
type unavailableDataBroker struct {
	databroker.DataBrokerServiceClient
}

func (unavailableDataBroker) Get(
	context.Context, *databroker.GetRequest, ...grpc.CallOption,
) (*databroker.GetResponse, error) {
	return nil, status.Error(codes.Unavailable, "databroker unavailable")
}

// RED (finding): getAgenticRunSession collapses a *transient* databroker error
// (codes.Unavailable) into sessions.ErrInvalidSession, which Check turns into a
// definitive 403. The sibling session path (loadSession → grpc.go:156) instead
// propagates codes.Unavailable as a retryable error. A valid, non-revoked run
// token presented during a brief databroker outage must NOT be permanently
// denied — the error should stay retryable, not become ErrInvalidSession.
func TestGetAgenticRunSession_TransientErrorNotInvalidSession(t *testing.T) {
	c, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
	require.NoError(t, err)

	// A perfectly valid, unexpired run token.
	tok, err := agentic.MintRunToken(c, "run-abc", time.Now().Add(time.Hour), 1)
	require.NoError(t, err)

	a := &Authorize{}
	a.state.Store(&authorizeState{
		agenticCipher:    c,
		dataBrokerClient: unavailableDataBroker{},
	})

	_, err = a.getAgenticRunSession(context.Background(), tok)
	require.Error(t, err)

	// The transient outage must be distinguishable from an invalid token.
	require.False(t, errors.Is(err, sessions.ErrInvalidSession),
		"a transient databroker Unavailable must not be reported as an invalid session (that becomes a permanent 403 for a valid token)")
	require.Equal(t, codes.Unavailable, status.Code(err),
		"the retryable gRPC status must be preserved so the request is not permanently denied")
}

// failingDataBroker fails every Get with a chosen status code.
type failingDataBroker struct {
	databroker.DataBrokerServiceClient
	code codes.Code
}

func (f failingDataBroker) Get(
	context.Context, *databroker.GetRequest, ...grpc.CallOption,
) (*databroker.GetResponse, error) {
	return nil, status.Error(f.code, "induced")
}

// TestGetAgenticRunSession_OnlyMissingRecordsAreInvalid extends the Unavailable
// case above to every other way the databroker read can fail.
//
// These reads inherit the ext_authz request context, so DeadlineExceeded and
// Canceled arrive here in normal operation — under load, or when the downstream
// client simply goes away. Treating anything other than "the record is not
// there" as an invalid credential answers an infrastructure failure with a
// definitive 403 and denies a valid run token.
func TestGetAgenticRunSession_OnlyMissingRecordsAreInvalid(t *testing.T) {
	c, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
	require.NoError(t, err)
	tok, err := agentic.MintRunToken(c, "run-abc", time.Now().Add(time.Hour), 1)
	require.NoError(t, err)

	for _, tc := range []struct {
		code    codes.Code
		invalid bool
	}{
		{codes.NotFound, true},
		{codes.Unavailable, false},
		{codes.DeadlineExceeded, false},
		{codes.Canceled, false},
		{codes.ResourceExhausted, false},
		{codes.Internal, false},
	} {
		t.Run(tc.code.String(), func(t *testing.T) {
			a := &Authorize{}
			a.state.Store(&authorizeState{
				agenticCipher:    c,
				dataBrokerClient: failingDataBroker{code: tc.code},
			})

			_, err := a.getAgenticRunSession(context.Background(), tok)
			require.Error(t, err)

			if tc.invalid {
				require.True(t, errors.Is(err, sessions.ErrInvalidSession),
					"a missing run record is a statement about the credential")
				return
			}
			require.False(t, errors.Is(err, sessions.ErrInvalidSession),
				"%s is an infrastructure failure; reporting it as an invalid session denies a valid run token", tc.code)
			require.Equal(t, tc.code, status.Code(err),
				"the original status must survive so the failure stays retryable")
		})
	}
}
