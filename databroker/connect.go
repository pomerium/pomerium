package databroker

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/databrokerconnect"
)

func (d *DataBroker) RegisterConnect(mux *http.ServeMux) {
	otelInterceptor, err := otelconnect.NewInterceptor(
		otelconnect.WithTracerProvider(d.tracerProvider),
	)
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	mux.Handle(databrokerconnect.NewCheckpointServiceHandler(checkpointServiceHandler{d},
		connect.WithInterceptors(otelInterceptor),
	))
}

type checkpointServiceHandler struct {
	*DataBroker
}

func (h checkpointServiceHandler) GetCheckpoint(
	ctx context.Context,
	req *connect.Request[databroker.GetCheckpointRequest],
) (*connect.Response[databroker.GetCheckpointResponse], error) {
	res, err := h.DataBroker.srv.GetCheckpoint(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (h checkpointServiceHandler) SetCheckpoint(
	ctx context.Context,
	req *connect.Request[databroker.SetCheckpointRequest],
) (*connect.Response[databroker.SetCheckpointResponse], error) {
	res, err := h.DataBroker.srv.SetCheckpoint(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}
