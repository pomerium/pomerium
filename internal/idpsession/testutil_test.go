package idpsession

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRecordSetComparisonHelpers(t *testing.T) {
	want := make(databroker.RecordSetBundle)
	want.Add(databroker.NewRecord(&session.Session{Id: "session-1", UserId: "user-1"}))
	want.Add(databroker.NewRecord(&user.User{Id: "user-1", Email: "user@example.com"}))

	got := make(databroker.RecordSetBundle)
	got.Add(databroker.NewRecord(&user.User{Id: "user-1", Email: "user@example.com"}))
	got.Add(databroker.NewRecord(&session.Session{Id: "session-1", UserId: "user-1"}))

	requireRecordSetBundleEqual(t, want, got)
	requireRecordSetEqual(
		t,
		want["type.googleapis.com/session.Session"],
		got["type.googleapis.com/session.Session"],
	)
	assertRecordSetBundleEqual(t, want, got)
	assertRecordSetEqual(
		t,
		want["type.googleapis.com/session.Session"],
		got["type.googleapis.com/session.Session"],
	)

	different := make(databroker.RecordSetBundle)
	different.Add(databroker.NewRecord(&session.Session{Id: "session-1", UserId: "user-2"}))
	different.Add(databroker.NewRecord(&user.User{Id: "user-1", Email: "user@example.com"}))

	assertRecordSetBundleNotEqual(t, want, different)
	requireRecordSetBundleNotEqual(t, want, different)
	assertRecordSetNotEqual(
		t,
		want["type.googleapis.com/session.Session"],
		different["type.googleapis.com/session.Session"],
	)
	requireRecordSetNotEqual(
		t,
		want["type.googleapis.com/session.Session"],
		different["type.googleapis.com/session.Session"],
	)
}

func assertRecordSetEqual(t testing.TB, want, got databroker.RecordSet) {
	t.Helper()
	assert.Empty(t, recordSetDiff(want, got), "record sets differ (-want +got)")
}

func requireRecordSetEqual(t testing.TB, want, got databroker.RecordSet) {
	t.Helper()
	require.Empty(t, recordSetDiff(want, got), "record sets differ (-want +got)")
}

func assertRecordSetNotEqual(t testing.TB, want, got databroker.RecordSet) {
	t.Helper()
	assert.NotEmpty(t, recordSetDiff(want, got), "record sets unexpectedly match")
}

func requireRecordSetNotEqual(t testing.TB, want, got databroker.RecordSet) {
	t.Helper()
	require.NotEmpty(t, recordSetDiff(want, got), "record sets unexpectedly match")
}

func assertRecordSetBundleEqual(t testing.TB, want, got databroker.RecordSetBundle) {
	t.Helper()
	assert.Empty(t, recordSetBundleDiff(want, got), "record-set bundles differ (-want +got)")
}

func requireRecordSetBundleEqual(t testing.TB, want, got databroker.RecordSetBundle) {
	t.Helper()
	require.Empty(t, recordSetBundleDiff(want, got), "record-set bundles differ (-want +got)")
}

func assertRecordSetBundleNotEqual(t testing.TB, want, got databroker.RecordSetBundle) {
	t.Helper()
	assert.NotEmpty(t, recordSetBundleDiff(want, got), "record-set bundles unexpectedly match")
}

func requireRecordSetBundleNotEqual(t testing.TB, want, got databroker.RecordSetBundle) {
	t.Helper()
	require.NotEmpty(t, recordSetBundleDiff(want, got), "record-set bundles unexpectedly match")
}

func recordSetDiff(want, got databroker.RecordSet) string {
	return cmp.Diff(want, got, protocmp.Transform())
}

func recordSetBundleDiff(want, got databroker.RecordSetBundle) string {
	return cmp.Diff(want, got, protocmp.Transform())
}
