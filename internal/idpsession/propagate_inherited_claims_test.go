package idpsession

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

// A bound session inherits every claim from its IdP session. When the IdP
// stops supplying a claim (the user was removed from a group and signed in
// again, which replaces the IdP session), propagation must drop it from the
// bound session: a stale group would still satisfy claim-based policies and
// still reach the upstream in JWT headers.
func TestPropagationRemovesInheritedClaims(t *testing.T) {
	now := time.Now()
	h := newSyncerReconcilerForTest(t, now, nil)

	upstream := newIDPSession("id1", nil, "token", now.Add(time.Hour))
	claims, err := structpb.NewStruct(map[string]any{"groups": []any{"admin"}, "email": "user@example.com"})
	require.NoError(t, err)
	upstream.Claims = claims
	records := append([]*databroker.Record{databroker.NewRecord(upstream)}, boundRecords(now, upstream.GetId())...)
	h.put(records...)
	h.reconcile()

	before, ok := assertGetRecord(t, h.client, &session.Session{Id: "s1"})
	require.True(t, ok)
	require.Contains(t, before.GetClaims(), "groups")

	upstream.Claims, err = structpb.NewStruct(map[string]any{"email": "user@example.com"})
	require.NoError(t, err)
	h.put(databroker.NewRecord(upstream))
	h.reconcile()

	after, ok := assertGetRecord(t, h.client, &session.Session{Id: "s1"})
	require.True(t, ok)
	assert.NotContains(t, after.GetClaims(), "groups", "a claim the IdP no longer supplies must not survive propagation")
	assert.Contains(t, after.GetClaims(), "email")
}
