package mux

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/internal/zero/apierror"
	"github.com/pomerium/pomerium/pkg/zero/connect"
)

// Watch watches for changes to the config until either context is canceled,
// or an error occurs while muxing
func (svc *Mux) Watch(ctx context.Context, opts ...WatchOption) error {
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-svc.ready:
	}

	cfg := newConfig(opts...)

	connected := svc.connected.Load()
	if connected {
		cfg.onConnected(ctx)
	} else {
		cfg.onDisconnected(ctx)
	}

	return svc.mux.Receive(ctx, func(ctx context.Context, msg message) error {
		return dispatch(ctx, cfg, msg)
	})
}

func dispatch(ctx context.Context, cfg *config, msg message) error {
	switch {
	case msg.stateChange != nil:
		switch *msg.stateChange {
		case connected:
			cfg.onConnected(ctx)
		case disconnected:
			cfg.onDisconnected(ctx)
		default:
			return fmt.Errorf("unknown state change")
		}
	case msg.Message != nil:
		switch msg.Message.Message.(type) {
		case *connect.Message_ConfigUpdated:
			cfg.onBundleUpdated(ctx, "config")
		case *connect.Message_BootstrapConfigUpdated:
			cfg.onBootstrapConfigUpdated(ctx)
		case *connect.Message_TelemetryRequest:
			cfg.onTelemetryRequested(ctx, msg.Message.GetTelemetryRequest())
		case *connect.Message_RunHealthChecksRequest:
			cfg.onRunHealthChecks(ctx)
		default:
			log.Ctx(ctx).Debug().Msg("unknown message type, ignored")
		}
	default:
		return fmt.Errorf("unknown message payload")
	}
	return nil
}

type message struct {
	*stateChange
	*connect.Message
}

func (msg message) String() string {
	var b strings.Builder
	if msg.stateChange != nil {
		b.WriteString("stateChange: ")
		b.WriteString(string(*msg.stateChange))
	}
	if msg.Message != nil {
		b.WriteString("message: ")
		b.WriteString(protojson.Format(msg.Message))
	}
	return b.String()
}

type stateChange string

const (
	connected    stateChange = "connected"
	disconnected stateChange = "disconnected"
)

// Publish publishes a message to the fanout
// we treat errors returned from the fanout as terminal,
// as they are generally non recoverable
func (svc *Mux) publish(ctx context.Context, msg message) error {
	err := svc.mux.Publish(ctx, msg)
	if err != nil {
		return apierror.NewTerminalError(err)
	}
	return nil
}

func (svc *Mux) onConnected(ctx context.Context) error {
	s := connected
	svc.connected.Store(true)
	err := svc.publish(ctx, message{stateChange: &s})
	if err != nil {
		return fmt.Errorf("onConnected: %w", err)
	}
	return nil
}

func (svc *Mux) onDisconnected(ctx context.Context) error {
	s := disconnected
	svc.connected.Store(false)
	err := svc.publish(ctx, message{stateChange: &s})
	if err != nil {
		return fmt.Errorf("onDisconnected: %w", err)
	}
	return nil
}

func (svc *Mux) onMessage(ctx context.Context, msg *connect.Message) error {
	err := svc.publish(ctx, message{Message: msg})
	if err != nil {
		return fmt.Errorf("onMessage: %w", err)
	}
	return nil
}
