package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/internal/log"
	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

var _ pb.Listener_StatusUpdatesServer = &jsonStream{}

type jsonStream struct {
	http.ResponseWriter
	protojson.MarshalOptions
	ctx context.Context
}

// ListenerUpdateStream creates http handler
func ListenerUpdateStream(srv pb.ListenerServer) runtime.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, param map[string]string) {
		sel, err := parseRequest(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			log.Error(r.Context()).Err(err).Msg("GET /updates")
			return
		}

		js := &jsonStream{
			ResponseWriter: w,
			ctx:            r.Context(),
		}
		w.Header().Add("content-type", "text/event-stream")
		w.Header().Add("cache-control", "no-cache")

		if err := srv.StatusUpdates(sel, js); err != nil {
			log.Error(r.Context()).Err(err).Msg("GET /updates")
		}
	}
}

func parseRequest(r *http.Request) (*pb.StatusUpdatesRequest, error) {
	defer func() {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}()

	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<15))
	if err != nil {
		return nil, err
	}

	sel := new(pb.StatusUpdatesRequest)
	if err = protojson.Unmarshal(data, sel); err != nil {
		return nil, err
	}
	return sel, nil
}

// Send sends a message as text event stream
// see https://html.spec.whatwg.org/multipage/server-sent-events.html#server-sent-events
func (s *jsonStream) Send(m *pb.ConnectionStatusUpdate) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}

	data, err := s.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return s.write([][]byte{
		[]byte("event: event\ndata: "),
		data,
		[]byte("\n\n\n")})
}

func (s *jsonStream) write(bytes [][]byte) error {
	for _, b := range bytes {
		_, err := s.Write(b)
		if err != nil {
			return err
		}
	}
	return nil
}

// SetHeader sets the header metadata. It may be called multiple times.
// When call multiple times, all the provided metadata will be merged.
// All the metadata will be sent out when one of the following happens:
//  - ServerStream.SendHeader() is called;
//  - The first response is sent out;
//  - An RPC status is sent out (error or success).
func (s *jsonStream) SetHeader(_ metadata.MD) error {
	return nil
}

// SendHeader sends the header metadata.
// The provided md and headers set by SetHeader() will be sent.
// It fails if called multiple times.
func (s *jsonStream) SendHeader(_ metadata.MD) error {
	return nil
}

// SetTrailer sets the trailer metadata which will be sent with the RPC status.
// When called more than once, all the provided metadata will be merged.
func (s *jsonStream) SetTrailer(_ metadata.MD) {}

// Context returns the context for this stream.
func (s *jsonStream) Context() context.Context {
	return s.ctx
}

// SendMsg sends a message. On error, SendMsg aborts the stream and the
// error is returned directly.
//
// SendMsg blocks until:
//   - There is sufficient flow control to schedule m with the transport, or
//   - The stream is done, or
//   - The stream breaks.
//
// SendMsg does not wait until the message is received by the client. An
// untimely stream closure may result in lost messages.
//
// It is safe to have a goroutine calling SendMsg and another goroutine
// calling RecvMsg on the same stream at the same time, but it is not safe
// to call SendMsg on the same stream in different goroutines.
func (s *jsonStream) SendMsg(m interface{}) error {
	return nil
}

// RecvMsg blocks until it receives a message into m or the stream is
// done. It returns io.EOF when the client has performed a CloseSend. On
// any non-EOF error, the stream is aborted and the error contains the
// RPC status.
//
// It is safe to have a goroutine calling SendMsg and another goroutine
// calling RecvMsg on the same stream at the same time, but it is not
// safe to call RecvMsg on the same stream in different goroutines.
func (s *jsonStream) RecvMsg(m interface{}) error {
	return nil
}
