package agentic

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agenticpb "github.com/pomerium/pomerium/internal/agentic/gen"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
	idpsessionpb "github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// putBindingRecord writes a binding record directly, so the test can put it in a
// revoked state without going through the approval flow.
func putBindingRecord(ctx context.Context, t *testing.T, client databroker_grpc.DataBrokerServiceClient, b *idpsessionpb.Binding) {
	t.Helper()
	data := protoutil.NewAny(b)
	_, err := client.Put(ctx, &databroker_grpc.PutRequest{Records: []*databroker_grpc.Record{{
		Id:   b.GetId(),
		Data: data,
		Type: data.GetTypeUrl(),
	}}})
	require.NoError(t, err)
}

// TestRunIsBoundReflectsTheBindingNotTheSeal pins what "bound" reports.
//
// bound_claims is the executor seal written at creation, so it is set on every
// properly sealed run — including one nobody approved — and stays set after the
// binding is revoked. Deriving the status from it told an orchestrator a pending
// or revoked run was live.
func TestRunIsBoundReflectsTheBindingNotTheSeal(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := newSealWindowDataBroker(ctx, t)
	h := &Handler{prefix: DefaultPrefix, client: databroker_grpc.NewStaticClientGetter(client)}

	// Every run here carries a full executor seal, which is the point: the seal
	// must not by itself make a run look bound.
	seal := map[string]*structpb.ListValue{
		"kubernetes.io.pod.uid": {Values: []*structpb.Value{structpb.NewStringValue("pod-uid-1")}},
	}
	newRun := func(id string, state agenticpb.RunState) *agenticpb.Run {
		run := &agenticpb.Run{
			Id:          id,
			State:       state,
			BoundClaims: seal,
			ExpiresAt:   timestamppb.New(time.Now().Add(time.Hour)),
		}
		require.NoError(t, PutRun(ctx, client, run))
		return run
	}

	t.Run("a sealed but unapproved run is not bound", func(t *testing.T) {
		run := newRun("run-pending", agenticpb.RunState_RUN_STATE_PENDING)
		require.NotEmpty(t, run.GetBoundClaims(), "the run is sealed")
		bound, err := h.runIsBound(ctx, run)
		require.NoError(t, err)
		assert.False(t, bound, "a run nobody approved has no binding")
	})

	t.Run("an approved run with no binding record is not bound", func(t *testing.T) {
		run := newRun("run-approved-nobinding", agenticpb.RunState_RUN_STATE_APPROVED)
		bound, err := h.runIsBound(ctx, run)
		require.NoError(t, err)
		assert.False(t, bound, "approval without a binding record cannot mint")
	})

	t.Run("an approved run with an active binding is bound, and stops being bound once revoked", func(t *testing.T) {
		run := newRun("run-approved", agenticpb.RunState_RUN_STATE_APPROVED)
		sid := SessionID(run.GetId())

		// Protocol is deliberately unset: runIsBound asks only whether a binding
		// exists and is unrevoked, which is protocol-agnostic.
		binding := &idpsessionpb.Binding{
			Id:           sid,
			IdpSessionId: "idp-session-1",
			InitiatedAt:  timestamppb.Now(),
		}
		putBindingRecord(ctx, t, client, binding)

		bound, err := h.runIsBound(ctx, run)
		require.NoError(t, err)
		require.True(t, bound, "an approved run with a live binding must report bound")

		putBindingRecord(ctx, t, client, binding.Revoke())

		bound, err = h.runIsBound(ctx, run)
		require.NoError(t, err)
		assert.False(t, bound,
			"a revoked binding must clear bound, even though bound_claims is unchanged")
		assert.NotEmpty(t, run.GetBoundClaims(), "the seal is still there")
	})
}
