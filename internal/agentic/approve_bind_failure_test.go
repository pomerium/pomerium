package agentic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	agenticpb "github.com/pomerium/pomerium/internal/agentic/gen"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/opaquetoken"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
	idpsessionpb "github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// failBoundRecordsClient fails the Put that writes the run's session and
// binding, leaving every other write alone.
type failBoundRecordsClient struct {
	databroker_grpc.DataBrokerServiceClient
	fail atomic.Bool
}

func (c *failBoundRecordsClient) Put(
	ctx context.Context, req *databroker_grpc.PutRequest, opts ...grpc.CallOption,
) (*databroker_grpc.PutResponse, error) {
	if c.fail.Load() {
		for _, rec := range req.GetRecords() {
			if rec.GetType() == protoutil.GetTypeURL(new(idpsessionpb.Binding)) {
				return nil, status.Error(codes.Unavailable, "injected binding failure")
			}
		}
	}
	return c.DataBrokerServiceClient.Put(ctx, req, opts...)
}

func approvalAssertion(t *testing.T, sessionID, userID string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte("test-secret-key-32-bytes-long!!")}, nil)
	require.NoError(t, err)
	raw, err := josejwt.Signed(signer).
		Claims(map[string]any{"sid": sessionID, "sub": userID}).CompactSerialize()
	require.NoError(t, err)
	return raw
}

// newApprovalFixture stands up everything ApprovePost reads: the approver's
// session, their centralized IdP session, a pending run, and a valid approval
// code. It returns a handler bound to client and a factory for fresh requests,
// since a form body can only be read once.
func newApprovalFixture(
	ctx context.Context, t *testing.T, client databroker_grpc.DataBrokerServiceClient, runID, userID string,
) (*Handler, func() *http.Request) {
	t.Helper()

	const sid = "session-1"
	_, err := session.Put(ctx, client, &session.Session{Id: sid, UserId: userID})
	require.NoError(t, err)

	_, err = client.Put(ctx, &databroker_grpc.PutRequest{
		Records: []*databroker_grpc.Record{
			databroker_grpc.NewRecord(&idpsessionpb.IDPSession{Id: userID}),
		},
	})
	require.NoError(t, err)

	require.NoError(t, PutRun(ctx, client, &agenticpb.Run{
		Id:        runID,
		State:     agenticpb.RunState_RUN_STATE_PENDING,
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}))

	cfg := config.New(&config.Options{SharedKey: cryptutil.NewBase64Key()})
	c, err := NewCipher(cfg)
	require.NoError(t, err)
	h := &Handler{
		prefix: DefaultPrefix,
		cfg:    cfg,
		client: databroker_grpc.NewStaticClientGetter(client),
		cipher: c,
	}

	code, err := opaquetoken.Seal(
		opaquetoken.TypeAuthorization, runID, time.Now().Add(time.Hour), "", c)
	require.NoError(t, err)

	return h, func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://agentic.example.com"+ApprovePath(DefaultPrefix),
			strings.NewReader(url.Values{"code": {code}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set(httputil.HeaderPomeriumJWTAssertion, approvalAssertion(t, sid, userID))
		return r.WithContext(ctx)
	}
}

// TestApprovePost_BindingFailureLeavesRunRetryable pins that a failed bound-record
// write does not permanently consume the approval.
//
// ApprovePost claims the run before it writes the session and binding, so that a
// losing approver can never overwrite the winner's records. That ordering is
// deliberate, but it means a failure of the second write would otherwise leave a
// run APPROVED with no binding: /token refuses to mint for it and a second
// approval is rejected as "run already approved", so the run is unusable and
// unrecoverable without editing the datastore by hand.
func TestApprovePost_BindingFailureLeavesRunRetryable(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	base := newSealWindowDataBroker(ctx, t)
	client := &failBoundRecordsClient{DataBrokerServiceClient: base}
	h, newRequest := newApprovalFixture(ctx, t, client, "run-1", "alice")

	client.fail.Store(true)
	first := httptest.NewRecorder()
	h.ApprovePost(first, newRequest())
	require.Equal(t, http.StatusInternalServerError, first.Code)

	run, _, err := GetRunRecordVersion(ctx, base, "run-1")
	require.NoError(t, err)
	assert.Equal(t, agenticpb.RunState_RUN_STATE_PENDING, run.GetState(),
		"a failed binding write must not permanently consume the approval")

	// The approver retries once the databroker recovers.
	client.fail.Store(false)
	retry := httptest.NewRecorder()
	h.ApprovePost(retry, newRequest())
	require.Equal(t, http.StatusSeeOther, retry.Code,
		"a completed approval hands the approver their client-bindings page")
	assert.Contains(t, retry.Header().Get("Location"), "highlight="+SessionID("run-1"),
		"the redirect points at the binding the approval created")

	_, err = idpsessionpb.GetActiveBinding(ctx, base, SessionID("run-1"))
	assert.NoError(t, err, "the retry must leave the run bound")
}
