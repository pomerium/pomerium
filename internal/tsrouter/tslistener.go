package tsrouter

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"time"

	"golang.org/x/sync/errgroup"
	"tailscale.com/tsnet"

	"github.com/cenkalti/backoff/v4"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

var errStopped = errors.New("stopped")

type tsListener struct {
	ServerAddr   string
	OutboundPort string
	ServiceName  string
	SignedJWTKey []byte
	Settings     config.TailscaleListenerSettings

	stop context.CancelCauseFunc
}

func (l *tsListener) Equal(other *tsListener) bool {
	if l == nil && other == nil {
		return true
	} else if l == nil || other == nil {
		return false
	}
	return l.ServerAddr == other.ServerAddr &&
		l.OutboundPort == other.OutboundPort &&
		l.ServiceName == other.ServiceName &&
		bytes.Equal(l.SignedJWTKey, other.SignedJWTKey) &&
		reflect.DeepEqual(l.Settings, other.Settings)
}

func (l *tsListener) Start(ctx context.Context) {
	log.Ctx(ctx).Info().
		Msg("tsrouter: starting listener")

	ctx, l.stop = context.WithCancelCause(ctx)

	cc, err := grpc.NewOutboundGRPCClientConn(ctx, &grpc.OutboundOptions{
		OutboundPort: l.OutboundPort,
		ServiceName:  l.ServiceName,
		SignedJWTKey: l.SignedJWTKey,
	})
	if errors.Is(err, errStopped) {
		return
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("tsrouter: error creating outbound grpc connection")
		return
	}

	srv := &tsnet.Server{
		Store:         NewDataBrokerStateStore(l.Settings.Hostname.Value, databrokerpb.NewDataBrokerServiceClient(cc)),
		Hostname:      l.Settings.Hostname.Value,
		Ephemeral:     l.Settings.Ephemeral.Value,
		AuthKey:       l.Settings.AuthKey.Value,
		ClientSecret:  l.Settings.OauthClientSecret.Value,
		ClientID:      l.Settings.OauthClientID.Value,
		IDToken:       l.Settings.IDToken.Value,
		Audience:      l.Settings.IDTokenAudience.Value,
		ControlURL:    l.Settings.ControlURL.Value,
		AdvertiseTags: l.Settings.Tags.Value,
		UserLogf: func(format string, args ...any) {
			log.Ctx(ctx).Info().Str("service", "tsrouter").Msgf(format, args...)
		},
		Logf: func(format string, args ...any) {
			log.Ctx(ctx).Debug().Str("service", "tsrouter").Msgf(format, args...)
		},
	}

	if l.Settings.ListenAddr.IsSet {
		log.Ctx(ctx).Info().
			Str("addr", l.Settings.ListenAddr.Value).
			Msg("tsrouter: starting tailnet listener")
		var li net.Listener
		var err error
		if l.Settings.TerminateTLS.Value {
			li, err = srv.ListenTLS("tcp", l.Settings.ListenAddr.Value)
		} else {
			li, err = srv.Listen("tcp", l.Settings.ListenAddr.Value)
		}
		if err != nil {
			log.Ctx(ctx).Error().
				Err(err).
				Str("addr", l.Settings.ListenAddr.Value).
				Msg("tsrouter: error starting tailnet listener")
			return
		} else {
			go l.handleListener(ctx, li)
		}
	}

	if l.Settings.ListenFunnelAddr.IsSet {
		log.Ctx(ctx).Info().
			Str("addr", l.Settings.ListenFunnelAddr.Value).
			Msg("tsrouter: starting funnel listener")
		funnelOptions := []tsnet.FunnelOption{tsnet.FunnelOnly()}
		if !l.Settings.TerminateTLS.Value {
			funnelOptions = append(funnelOptions, tsnet.FunnelTLSConfig(&tls.Config{
				GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
					return nil, fmt.Errorf("not implemented")
				},
			}))
		}
		li, err := srv.ListenFunnel("tcp", l.Settings.ListenFunnelAddr.Value, funnelOptions...)
		if err != nil {
			log.Ctx(ctx).Error().
				Err(err).
				Str("addr", l.Settings.ListenFunnelAddr.Value).
				Msg("tsrouter: error starting funnel listener")
		} else {
			go l.handleListener(ctx, li)
		}
	}

	if l.Settings.ListenServiceName.IsSet {
		log.Ctx(ctx).Info().
			Str("service-name", l.Settings.ListenServiceName.Value).
			Uint32("service-port", l.Settings.ListenServicePort.Value).
			Msg("tsrouter: starting service listener")
		li, err := srv.ListenService(l.Settings.ListenServiceName.Value, tsnet.ServiceModeTCP{
			Port:         uint16(l.Settings.ListenServicePort.Value),
			TerminateTLS: l.Settings.TerminateTLS.Value,
		})
		if err != nil {
			log.Ctx(ctx).Error().
				Err(err).
				Str("service-name", l.Settings.ListenServiceName.Value).
				Uint32("service-port", l.Settings.ListenServicePort.Value).
				Msg("tsrouter: error starting service listener")
		} else {
			go l.handleListener(ctx, li)
		}
	}
}

func (l *tsListener) Stop() {
	log.Info().Msg("tsrouter: stopping listener")
	if l.stop != nil {
		l.stop(errStopped)
	}
}

func (l *tsListener) handleListener(ctx context.Context, li net.Listener) {
	cleanup := context.AfterFunc(ctx, func() { _ = li.Close() })
	defer cleanup()

	b := backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(0))
	for {
		conn, err := li.Accept()
		if err == nil {
			b.Reset()
			go l.handleConn(ctx, conn)
		} else {
			log.Ctx(ctx).Error().
				Err(err).
				Msg("tsrouter: error accepting connection")
			select {
			case <-ctx.Done():
				return
			case <-time.After(b.NextBackOff()):
			}
		}
	}
}

func (l *tsListener) handleConn(ctx context.Context, remote net.Conn) {
	log.Ctx(ctx).Info().
		Str("local-addr", remote.LocalAddr().String()).
		Str("remote-addr", remote.RemoteAddr().String()).
		Msg("tsrouter: incoming connection")

	defer remote.Close()
	cleanupRemote := context.AfterFunc(ctx, func() { _ = remote.Close() })
	defer cleanupRemote()

	var local net.Conn
	var err error
	if !l.Settings.TerminateTLS.Value {
		var d net.Dialer
		local, err = d.DialContext(ctx, "tcp", l.ServerAddr)
	} else {
		var d tls.Dialer
		d.Config = &tls.Config{InsecureSkipVerify: true}
		local, err = d.DialContext(ctx, "tcp", l.ServerAddr)
	}
	if err != nil {
		select {
		case <-ctx.Done():
			return
		default:
		}
		log.Ctx(ctx).Error().
			Str("server-addr", l.ServerAddr).
			Msg("tsrouter: error connecting to server")
		return
	}

	defer local.Close()
	cleanupLocal := context.AfterFunc(ctx, func() { _ = local.Close() })
	defer cleanupLocal()

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { _, err := io.Copy(local, remote); return err })
	eg.Go(func() error { _, err := io.Copy(remote, local); return err })
	_ = eg.Wait()
}
