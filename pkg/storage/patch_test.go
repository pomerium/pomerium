package storage_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestPatchRecord(t *testing.T) {
	t.Parallel()

	tm := timestamppb.New(time.Date(2023, 10, 31, 12, 0, 0, 0, time.UTC))

	s1 := &session.Session{Id: "session-id"}
	a1, _ := anypb.New(s1)
	r1 := &databroker.Record{Data: a1}

	s2 := &session.Session{Id: "new-session-id", AccessedAt: tm}
	a2, _ := anypb.New(s2)
	r2 := &databroker.Record{Data: a2}

	originalR1 := proto.Clone(r1).(*databroker.Record)

	m, _ := fieldmaskpb.New(&session.Session{}, "accessed_at")

	storage.PatchRecord(r1, r2, m)

	testutil.AssertProtoJSONEqual(t, `{
		"data": {
			"@type": "type.googleapis.com/session.Session",
			"accessedAt": "2023-10-31T12:00:00Z",
			"id": "session-id"
		}
	}`, r2)

	// The existing record should not be modified.
	testutil.AssertProtoEqual(t, originalR1, r1)
}
