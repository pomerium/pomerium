package reconciler_test

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/wrapperspb"

	databroker_int "github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/zero/reconciler"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func newDatabroker(t *testing.T) (context.Context, databroker.DataBrokerServiceClient) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	gs := grpc.NewServer()
	srv := databroker_int.New()

	databroker.RegisterDataBrokerServiceServer(gs, srv)

	lis := bufconn.Listen(1)
	t.Cleanup(func() {
		lis.Close()
		gs.Stop()
	})

	go func() { _ = gs.Serve(lis) }()

	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (conn net.Conn, e error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return ctx, databroker.NewDataBrokerServiceClient(conn)
}

func newRecordBundle(records []testRecord) reconciler.RecordSetBundle[reconciler.DatabrokerRecord] {
	bundle := make(reconciler.RecordSetBundle[reconciler.DatabrokerRecord])
	for _, r := range records {
		bundle.Add(newRecord(r))
	}
	return bundle
}

func newRecord(r testRecord) reconciler.DatabrokerRecord {
	return reconciler.DatabrokerRecord{
		V: &databroker.Record{
			Type: r.Type,
			Id:   r.ID,
			Data: protoutil.NewAnyString(r.Val),
		}}
}

func assertBundle(t *testing.T, want []testRecord, got reconciler.RecordSetBundle[reconciler.DatabrokerRecord]) {
	t.Helper()

	for _, wantRecord := range want {
		gotRecord, ok := got.Get(wantRecord.Type, wantRecord.ID)
		if assert.True(t, ok, "record %s/%s not found", wantRecord.Type, wantRecord.ID) {
			assertRecord(t, wantRecord, gotRecord)
		}
	}
	assert.Len(t, got.Flatten(), len(want))
}

func assertRecord(t *testing.T, want testRecord, got reconciler.DatabrokerRecord) {
	t.Helper()

	var val wrapperspb.StringValue
	err := got.V.Data.UnmarshalTo(&val)
	require.NoError(t, err)

	assert.Equal(t, want.Type, got.V.Type)
	assert.Equal(t, want.ID, got.V.Id)
	assert.Equal(t, want.Val, val.Value)
}

func TestHelpers(t *testing.T) {
	want := []testRecord{
		{"type1", "id1", "value1"},
		{"type1", "id2", "value2"},
	}

	bundle := newRecordBundle(want)
	assertBundle(t, want, bundle)
}

func wantRemoved(want, current []string) []string {
	wantM := make(map[string]struct{}, len(want))
	for _, w := range want {
		wantM[w] = struct{}{}
	}
	var toRemove []string
	for _, c := range current {
		if _, ok := wantM[c]; !ok {
			toRemove = append(toRemove, c)
		}
	}
	return toRemove
}

func reconcile(
	ctx context.Context,
	t *testing.T,
	client databroker.DataBrokerServiceClient,
	want []testRecord,
	current reconciler.RecordSetBundle[reconciler.DatabrokerRecord],
) reconciler.RecordSetBundle[reconciler.DatabrokerRecord] {
	t.Helper()

	wantBundle := newRecordBundle(want)
	err := reconciler.Reconcile(ctx, client, wantBundle, current)
	require.NoError(t, err)

	got, err := reconciler.GetDatabrokerRecords(ctx, client, wantBundle.RecordTypes())
	require.NoError(t, err)
	assertBundle(t, want, got)

	res, err := reconciler.GetDatabrokerRecords(ctx, client, wantRemoved(wantBundle.RecordTypes(), current.RecordTypes()))
	require.NoError(t, err)
	assert.Empty(t, res.Flatten())

	return got
}

func TestReconcile(t *testing.T) {
	t.Parallel()

	ctx, client := newDatabroker(t)

	err := reconciler.Reconcile(ctx, client, nil, nil)
	require.NoError(t, err)

	var current reconciler.RecordSetBundle[reconciler.DatabrokerRecord]
	for _, tc := range []struct {
		name string
		want []testRecord
	}{
		{"empty", nil},
		{"initial", []testRecord{
			{"type1", "id1", "value1"},
			{"type1", "id2", "value2"},
		}},
		{"add one", []testRecord{
			{"type1", "id1", "value1"},
			{"type1", "id2", "value2"},
			{"type1", "id3", "value3"},
		}},
		{"update one", []testRecord{
			{"type1", "id1", "value1"},
			{"type1", "id2", "value2-updated"},
			{"type1", "id3", "value3"},
		}},
		{"delete one", []testRecord{
			{"type1", "id1", "value1"},
			{"type1", "id3", "value3"},
		}},
		{"delete all", nil},
		{"multiple types", []testRecord{
			{"type1", "id1", "value1"},
			{"type1", "id2", "value2"},
			{"type2", "id1", "value1"},
			{"type2", "id2", "value2"},
		}},
		{"multiple types update", []testRecord{
			{"type1", "id1", "value1"},
			{"type1", "id2", "value2-updated"},
			{"type2", "id1", "value1"},
			{"type2", "id2", "value2-updated"},
		}},
		{"multiple types delete", []testRecord{
			{"type1", "id1", "value1"},
			{"type2", "id1", "value1"},
		}},
		{"multiple types delete one type, add one value", []testRecord{
			{"type1", "id1", "value1"},
			{"type1", "id4", "value4"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current = reconcile(ctx, t, client, tc.want, current)
		})
	}
}
