package pending

import (
	"context"
	"log/slog"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type distributedCodeAccessor struct {
	client databroker.DataBrokerServiceClient
}

var _ CodeAcessor = (*distributedCodeAccessor)(nil)

func NewDistributedCodeAccessor(
	client databroker.DataBrokerServiceClient,
) *distributedCodeAccessor {
	return &distributedCodeAccessor{
		client: client,
	}
}

type IdentitySessionPair struct {
	SB *session.SessionBinding
	IB *session.IdentityBinding
}

func (d *distributedCodeAccessor) RevokeSession(ctx context.Context, sessionID string) error {
	ibResp, err := d.client.Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/session.IdentityBinding",
		Id:   sessionID,
	})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			// this is fine
			ibResp = nil
		} else {
			slog.Default().With("err", err).Error("failed to fetch identity binding")
			return err
		}
	}

	sbResp, err := d.client.Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/session.SessionBinding",
		Id:   sessionID,
	})

	if err != nil {
		slog.Default().With("err", err).Error("failed to fetch session binding")
		return err
	}

	toDelete := []*databroker.Record{}
	sbRec := sbResp.GetRecord()
	if sbRec.DeletedAt == nil {
		sbRec.DeletedAt = timestamppb.Now()
		toDelete = append(toDelete, sbRec)
	}
	if ibResp != nil {
		ibRec := ibResp.GetRecord()
		if ibRec.DeletedAt == nil {
			ibRec.DeletedAt = timestamppb.Now()
			toDelete = append(toDelete, ibRec)
		}
	}

	if len(toDelete) > 0 {
		_, err = d.client.Put(ctx, &databroker.PutRequest{
			Records: toDelete,
		})
		return err
	}
	return nil
}

func (d *distributedCodeAccessor) GetSessionById(ctx context.Context, userID string) (map[SessionID]*IdentitySessionPair, error) {
	return d.GetSessionByIdRemote(ctx, userID)
}

func (d *distributedCodeAccessor) GetSessionByIdRemote(ctx context.Context, userID string) (map[SessionID]*IdentitySessionPair, error) {
	ret := map[SessionID]*IdentitySessionPair{}
	filterByUser := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"$or": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{
				structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
					"user_id": structpb.NewStringValue(userID),
				}}),
			}}),
		},
	}

	sessBindingRecs, err := d.client.Query(ctx, &databroker.QueryRequest{
		Type:   "type.googleapis.com/session.SessionBinding",
		Filter: filterByUser,
		Offset: 0,
		Limit:  10,
	})

	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		return ret, nil
	}
	if err != nil {
		return nil, err
	}

	identityBindingRecs, err := d.client.Query(ctx, &databroker.QueryRequest{
		Type:   "type.googleapis.com/session.IdentityBinding",
		Filter: filterByUser,
		Offset: 0,
		Limit:  10,
	})
	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		identityBindingRecs = &databroker.QueryResponse{
			Records: []*databroker.Record{},
		}
	} else if err != nil {
		return nil, err
	}

	for _, sb := range sessBindingRecs.GetRecords() {
		var sess session.SessionBinding
		if err := sb.GetData().UnmarshalTo(&sess); err != nil {
			panic(err)
		}
		sessionID := SessionID(sb.GetId())
		ret[sessionID] = &IdentitySessionPair{
			SB: &sess,
		}
	}

	for _, ib := range identityBindingRecs.GetRecords() {
		var ident session.IdentityBinding
		if err := ib.GetData().UnmarshalTo(&ident); err != nil {
			panic(err)
		}
		sessionID := SessionID(ib.GetId())
		val, ok := ret[sessionID]
		if !ok {
			val = &IdentitySessionPair{}
		}
		val.IB = &ident
	}
	return ret, nil
}

func (d *distributedCodeAccessor) GetBindingRequest(ctx context.Context, codeId CodeID) (*session.SessionBindingRequest, bool) {
	rec, err := d.client.Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/session.SessionBindingRequest",
		Id:   string(codeId),
	})
	if err != nil {
		return nil, false
	}
	var sess session.SessionBindingRequest
	if err := rec.Record.GetData().UnmarshalTo(&sess); err != nil {
		panic(err)
	}
	return &sess, true
}

func (d *distributedCodeAccessor) RevokeCode(ctx context.Context, codeId CodeID) error {
	slog.Default().With("codeId", codeId).Info("revoking code")
	rec, err := d.client.Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/session.SessionBindingRequest",
		Id:   string(codeId),
	})
	if err != nil {
		return err
	}

	if rec.Record.DeletedAt != nil {
		return nil
	}
	rec.Record.DeletedAt = timestamppb.Now()
	_, err = d.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{
			rec.Record,
		},
	})
	return err
}
