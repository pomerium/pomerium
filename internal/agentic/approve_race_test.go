package agentic

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	agenticpb "github.com/pomerium/pomerium/internal/agentic/gen"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// TestApprovalIsSingleUseUnderConcurrency pins "first approval wins".
//
// The pending check in ApprovePost cannot enforce it on its own: two approvers
// can both read a PENDING run and both pass. The commit is therefore conditional
// on the version the run was read at, so exactly one of them writes.
func TestApprovalIsSingleUseUnderConcurrency(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := newSealWindowDataBroker(ctx, t)

	require.NoError(t, PutRun(ctx, client, &agenticpb.Run{
		Id:        "run-contended",
		State:     agenticpb.RunState_RUN_STATE_PENDING,
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}))

	// Both approvers read the same version, as two browsers on the consent page do.
	run, version, err := GetRunRecordVersion(ctx, client, "run-contended")
	require.NoError(t, err)
	require.Equal(t, agenticpb.RunState_RUN_STATE_PENDING, run.GetState())

	const approvers = 4
	var (
		start           sync.WaitGroup
		done            sync.WaitGroup
		mu              sync.Mutex
		won             []string
		mismatches, oth int
	)
	start.Add(1)
	for i, who := range []string{"alice", "bob", "carol", "dave"} {
		done.Add(1)
		go func(who string) {
			defer done.Done()
			start.Wait()
			claimed := &agenticpb.Run{
				Id:        run.GetId(),
				State:     agenticpb.RunState_RUN_STATE_APPROVED,
				Sub:       who,
				ExpiresAt: run.GetExpiresAt(),
			}
			err := PutRunIfUnchanged(ctx, client, claimed, version)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won = append(won, who)
			case databroker.IsRecordVersionMismatch(err):
				mismatches++
			default:
				oth++
			}
		}(who)
		_ = i
	}
	start.Done()
	done.Wait()

	require.Empty(t, oth, "no approver may fail for a reason other than losing the race")
	require.Len(t, won, 1, "exactly one approver may commit, got %v", won)
	assert.Equal(t, approvers-1, mismatches, "every other approver must see a version mismatch")

	// The stored run belongs to the winner and nobody else.
	stored, _, err := GetRunRecordVersion(ctx, client, run.GetId())
	require.NoError(t, err)
	assert.Equal(t, agenticpb.RunState_RUN_STATE_APPROVED, stored.GetState())
	assert.Equal(t, won[0], stored.GetSub(),
		"run.Sub must be the approver who won, never a later one")
}
