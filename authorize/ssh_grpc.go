package authorize

import (
	"context"
	"errors"
	"io"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/ssh"
	"github.com/pomerium/pomerium/pkg/storage"
)

func (a *Authorize) ManageStream(stream extensions_ssh.StreamManagement_ManageStreamServer) error {
	event, err := stream.Recv()
	if err != nil {
		return err
	}
	// first message should be a downstream connected event
	downstream := event.GetEvent().GetDownstreamConnected()
	if downstream == nil {
		return status.Errorf(codes.Internal, "first message was not a downstream connected event")
	}

	handler := a.ssh.NewStreamHandler(stream.Context(), downstream)
	defer handler.Close()

	eg, ctx := errgroup.WithContext(stream.Context())

	eg.Go(func() error {
		for {
			req, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			handler.ReadC() <- req
		}
	})

	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case msg, ok := <-handler.WriteC():
				if !ok {
					// StreamHandler.close() called, no more messages to send
					return nil
				}
				if err := stream.Send(msg); err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					}
					return err
				}
			}
		}
	})

	return handler.Run(ctx)
}

func (a *Authorize) ServeChannel(stream extensions_ssh.StreamManagement_ServeChannelServer) error {
	metadata, err := stream.Recv()
	if err != nil {
		return err
	}
	// first message contains metadata
	var typedMd extensions_ssh.FilterMetadata
	if md := metadata.GetMetadata(); md != nil {
		if err := md.GetTypedFilterMetadata()["com.pomerium.ssh"].UnmarshalTo(&typedMd); err != nil {
			return err
		}
	} else {
		return status.Errorf(codes.Internal, "first message was not metadata")
	}
	handler := a.ssh.LookupStream(typedMd.GetStreamId())
	if handler == nil || !handler.IsExpectingInternalChannel() {
		return status.Errorf(codes.InvalidArgument, "stream not found")
	}

	return handler.ServeChannel(stream, &typedMd)
}

func (a *Authorize) EvaluateSSH(ctx context.Context, streamID uint64, req ssh.AuthRequest, initialAuthComplete bool) (*evaluator.Result, error) {
	ctx = a.withQuerierForCheckRequest(ctx)

	sessionID := ""
	// this checks to make sure if the binding ID was never set,
	// then the criteria will return un-authenticated
	if req.SessionBindingID != "" && req.SessionID != "" {
		sessionID = req.SessionID
	}

	evalreq := evaluator.Request{
		HTTP: evaluator.RequestHTTP{
			Hostname: req.Hostname,
			IP:       req.SourceAddress,
		},
		SSH: evaluator.RequestSSH{
			Username:  req.Username,
			PublicKey: []byte(req.PublicKey),
		},
		Session: evaluator.RequestSession{
			ID: sessionID,
		},
	}

	if req.Hostname == "" {
		evalreq.IsInternal = true
	} else {
		evalreq.Policy = a.currentConfig.Load().Options.GetRouteForSSHHostname(req.Hostname)
	}

	res, err := a.state.Load().evaluator.Evaluate(ctx, &evalreq)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("error during OPA evaluation")
		return nil, err
	}

	allowed := res.Allow.Value && !res.Deny.Value

	if allowed && !initialAuthComplete {
		if err := a.ssh.OnStreamAuthenticated(ctx, streamID, req); err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("failed to set session id for stream")
			return nil, err
		}
	}

	skipLogging := req.LogOnlyIfDenied && allowed
	if !skipLogging {
		s, _ := a.getDataBrokerSessionOrServiceAccount(ctx, req.SessionID, 0)
		a.logAuthorizeCheck(ctx, &evalreq, res, s)
	}

	return res, nil
}

func (a *Authorize) EvaluateUpstreamTunnel(_ context.Context, _ ssh.AuthRequest, _ *config.Policy) (*evaluator.Result, error) {
	// XXX: temporary stub
	return &evaluator.Result{
		Allow: evaluator.NewRuleResult(true),
		Deny:  evaluator.NewRuleResult(false),
	}, nil
}

func (a *Authorize) InvalidateCacheForRecords(ctx context.Context, records ...*databroker.Record) {
	storage.InvalidateCacheForDataBrokerRecords(a.withQuerierForCheckRequest(ctx), records...)
}
