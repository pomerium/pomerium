package code

import (
	"context"
	"slices"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

type Tuple2[A, B any] struct {
	A A
	B B
}

func T2[A, B any](a A, b B) Tuple2[A, B] {
	return Tuple2[A, B]{A: a, B: b}
}

func indexedFieldFilter(field, value string) (filter *structpb.Struct) {
	filter, _ = structpb.NewStruct(map[string]any{
		field: map[string]any{
			"$eq": value,
		},
	})
	return
}

func getSbrByFingerprintBuilder(fingerprintID string) *databroker.QueryRequest {
	filter := indexedFieldFilter("key", fingerprintID)
	return &databroker.QueryRequest{
		Type:   "type.googleapis.com/session.SessionBindingRequest",
		Filter: filter,
		Limit:  queryLimit,
	}
}

func getSbBySessionBuilder(sessionID string) *databroker.QueryRequest {
	filter := indexedFieldFilter("session_id", sessionID)
	return &databroker.QueryRequest{
		Type:   "type.googleapis.com/session.SessionBinding",
		Filter: filter,
		Limit:  queryLimit,
	}
}

func getCodeByBindingKey(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	fingerprintID string,
) (CodeID, error) {
	now := time.Now()
	qr, err := client.Query(ctx, getSbrByFingerprintBuilder(fingerprintID))
	if err != nil {
		return "", err
	}
	if len(qr.GetRecords()) == 0 {
		return "", nil
	}
	ret := make([]Tuple2[CodeID, *session.SessionBindingRequest], 0, len(qr.Records))
	for _, rec := range qr.GetRecords() {
		if rec.GetDeletedAt() != nil {
			continue
		}
		s := &session.SessionBindingRequest{}
		if err := rec.GetData().UnmarshalTo(s); err != nil {
			log.Err(err).Ctx(ctx).Msg("getCodeByBindingKey : failed to unmarshal session binding request")
			continue
		}
		if s.ExpiresAt.AsTime().Before(now) {
			continue
		}
		if s.State != session.SessionBindingRequestState_InFlight {
			// already processed
			continue
		}
		ret = append(ret, T2(CodeID(rec.GetId()), s))
	}

	slices.SortFunc(ret, func(a, b Tuple2[CodeID, *session.SessionBindingRequest]) int {
		return a.B.GetCreatedAt().AsTime().Compare(b.B.CreatedAt.AsTime())
	})

	if len(ret) == 0 {
		return "", status.Error(codes.NotFound, "no valid codes")
	}

	n := len(ret) - 1
	return ret[n].A, nil
}

func getSessionBindingBySession(ctx context.Context, client databroker.DataBrokerServiceClient, sessionID string) ([]*databroker.Record, error) {
	qr, err := client.Query(ctx, getSbBySessionBuilder(sessionID))
	if err != nil {
		return nil, err
	}
	return qr.GetRecords(), nil
}
