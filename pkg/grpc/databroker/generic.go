package databroker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"

	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// A GenericRecord is a record with its associated unmarshaled object.
type GenericRecord[T proto.Message] struct {
	*Record
	Object T
}

// IterateAll iterates through all the records using a SyncLatest call.
func IterateAll[T any, TMessage interface {
	*T
	proto.Message
}](
	ctx context.Context,
	client DataBrokerServiceClient,
) iter.Seq2[GenericRecord[TMessage], error] {
	var zero GenericRecord[TMessage]
	return func(yield func(GenericRecord[TMessage], error) bool) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		var msg any = new(T)
		stream, err := client.SyncLatest(ctx, &SyncLatestRequest{
			Type: protoutil.GetTypeURL(msg.(TMessage)),
		})
		if err != nil {
			_ = yield(zero, err)
			return
		}

		for {
			res, err := stream.Recv()
			switch {
			case errors.Is(err, io.EOF):
				// all done
				return
			case err != nil:
				_ = yield(zero, err)
				return
			}

			switch res := res.GetResponse().(type) {
			case *SyncLatestResponse_Versions:
				// ignore versions
				continue
			case *SyncLatestResponse_Record:
				// ignore records with no data
				if res.Record.GetData() == nil {
					continue
				}

				gr := GenericRecord[TMessage]{
					Record: res.Record,
				}
				var msg any = new(T)
				gr.Object = msg.(TMessage)
				err = res.Record.GetData().UnmarshalTo(gr.Object)
				if err != nil {
					log.Error(ctx).Err(err).Str("record-type", res.Record.GetType()).Str("record-id", res.Record.GetId()).Msg("databroker: unexpected object found in databroker record")
				} else if !yield(gr, nil) {
					return
				}
			default:
				panic(fmt.Sprintf("unexpected response: %T", res))
			}
		}
	}
}
