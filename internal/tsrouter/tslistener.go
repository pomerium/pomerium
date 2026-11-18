package tsrouter

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"tailscale.com/tsnet"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

var errStopped = errors.New("stopped")

type tsListener struct {
	ServerAddr string
	Settings   config.TailscaleListenerSettings

	telemetry      telemetry.Component
	certificates   atomic.Pointer[[]tls.Certificate]
	tsRouterConfig *tsRouterConfig
	cc             *grpc.ClientConn

	stop context.CancelCauseFunc
	wg   sync.WaitGroup
}

func newTSListener(
	tracerProvider oteltrace.TracerProvider,
	cfg *config.Config,
	settings config.TailscaleListenerSettings,
	tsRouterConfig *tsRouterConfig,
	cc *grpc.ClientConn,
) (*tsListener, error) {
	l := &tsListener{
		telemetry: *telemetry.NewComponent(tracerProvider, zerolog.InfoLevel, "tslistener",
			attribute.String("hostname", settings.Hostname.Value)),
		cc:             cc,
		tsRouterConfig: tsRouterConfig,
	}
	return l, l.init(cfg, settings)
}

func (l *tsListener) Equal(other *tsListener) bool {
	if l == nil && other == nil {
		return true
	} else if l == nil || other == nil {
		return false
	}
	return l.ServerAddr == other.ServerAddr &&
		l.cc == other.cc &&
		reflect.DeepEqual(l.Settings, other.Settings)
}

func (l *tsListener) Start(ctx context.Context) {
	_, op := l.telemetry.Start(ctx, "Start")
	defer op.Complete()

	ctx, l.stop = context.WithCancelCause(ctx)

	// the actual tsnet listener is run within a lease so that only one Pomerium Proxy
	// node will handle each host
	l.wg.Go(func() {
		_ = databrokerutil.NewLeasers("tslistener/"+l.Settings.Hostname.Value, 30*time.Second,
			databroker.NewDataBrokerServiceClient(l.cc),
			func(ctx context.Context) error {
				return l.runLeased(ctx)
			}).Run(ctx)
	})
}

func (l *tsListener) Stop() {
	if l.stop != nil {
		log.Info().Msg("tsrouter: stopping listener")
		l.stop(errStopped)
		l.wg.Wait()
	}
}

func (l *tsListener) init(cfg *config.Config, settings config.TailscaleListenerSettings) error {
	_, op := l.telemetry.Start(context.Background(), "init")
	defer op.Complete()

	l.ServerAddr = cfg.Options.Addr
	l.Settings = settings

	// store the certificates
	certs, err := cfg.AllCertificates()
	if err != nil {
		return op.Failure(fmt.Errorf("error loading certificates: %w", err))
	}
	catchAll, err := cfg.GenerateCatchAllCertificate()
	if err != nil {
		return op.Failure(fmt.Errorf("error generating catch-all certificate: %w", err))
	}
	l.certificates.Store(new(append(slices.Clone(certs), *catchAll)))

	return nil
}

func (l *tsListener) runLeased(ctx context.Context) error {
	opCtx, op := l.telemetry.Start(ctx, "runLeased",
		attribute.String("listen-addr", l.Settings.ListenAddr.Value),
		attribute.String("listen-funnel-addr", l.Settings.ListenFunnelAddr.Value),
		attribute.String("listen-service-name", l.Settings.ListenServiceName.Value))
	defer op.Complete()

	log.Ctx(opCtx).Info().Msg("tsrouter: starting listener")

	dir := filepath.Join(l.tsRouterConfig.directory, l.Settings.Hostname.Value)
	srv := &tsnet.Server{
		Dir:           dir,
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
			l.telemetry.Logger(ctx).Info().Msgf(format, args...)
		},
		Logf: func(format string, args ...any) {
			l.telemetry.Logger(ctx).Debug().Msgf(format, args...)
		},
	}
	defer srv.Close()

	if l.Settings.ListenAddr.IsSet {
		log.Ctx(opCtx).Info().Msg("starting tailnet listener")
		var li net.Listener
		var err error
		if l.Settings.TerminateTLS.Value {
			li, err = srv.ListenTLS("tcp", l.Settings.ListenAddr.Value)
		} else {
			li, err = srv.Listen("tcp", l.Settings.ListenAddr.Value)
		}
		if err != nil {
			return op.Failure(fmt.Errorf("failed to start tailnet listener: %w", err))
		}
		l.wg.Go(func() { l.handleListener(ctx, li, !l.Settings.TerminateTLS.Value) })
	}

	if l.Settings.ListenFunnelAddr.IsSet {
		log.Ctx(opCtx).Info().Msg("starting funnel listener")
		funnelOptions := []tsnet.FunnelOption{tsnet.FunnelOnly()}
		if !l.Settings.TerminateTLS.Value {
			funnelOptions = append(funnelOptions, tsnet.FunnelTLSConfig(&tls.Config{
				GetCertificate: l.getCertificate,
			}))
		}
		li, err := srv.ListenFunnel("tcp", l.Settings.ListenFunnelAddr.Value, funnelOptions...)
		if err != nil {
			return op.Failure(fmt.Errorf("failed to start tailnet funnel listener: %w", err))
		}
		l.wg.Go(func() { l.handleListener(ctx, li, false) })
	}

	if l.Settings.ListenServiceName.IsSet {
		log.Ctx(opCtx).Info().Msg("starting service listener")
		li, err := srv.ListenService(l.Settings.ListenServiceName.Value, tsnet.ServiceModeTCP{
			Port:         uint16(l.Settings.ListenServicePort.Value),
			TerminateTLS: l.Settings.TerminateTLS.Value,
		})
		if err != nil {
			return op.Failure(fmt.Errorf("failed to start tailnet service listener: %w", err))
		}
		l.wg.Go(func() { l.handleListener(ctx, li, !l.Settings.TerminateTLS.Value) })
	}

	<-ctx.Done()
	return context.Cause(ctx)
}

func (l *tsListener) handleListener(ctx context.Context, li net.Listener, rawTCP bool) {
	cleanup := context.AfterFunc(ctx, func() { _ = li.Close() })
	defer cleanup()

	b := backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(0))
	for {
		conn, err := li.Accept()
		if err == nil {
			b.Reset()
			l.wg.Go(func() { l.handleConn(ctx, conn, rawTCP) })
		} else {
			// if the reason we got an error is because the context is done, just return
			select {
			case <-ctx.Done():
				return
			default:
			}

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

func (l *tsListener) handleConn(ctx context.Context, remote net.Conn, rawTCP bool) {
	ctx, op := l.telemetry.Start(ctx, "handleConn",
		attribute.String("local-addr", remote.LocalAddr().String()),
		attribute.String("remote-addr", remote.RemoteAddr().String()),
		attribute.String("server-addr", l.ServerAddr))
	defer op.Complete()

	log.Ctx(ctx).Info().Msg("incoming connection")

	defer remote.Close()
	cleanupRemote := context.AfterFunc(ctx, func() { _ = remote.Close() })
	defer cleanupRemote()

	var local net.Conn
	var err error
	if rawTCP {
		// raw TCP means that Pomerium needs to terminate TLS, so we just proxy
		// the traffic directly
		var d net.Dialer
		local, err = d.DialContext(ctx, "tcp", l.ServerAddr)
	} else {
		// in this mode Tailscale is terminating TLS, so we need to make a TLS
		// connection to Pomerium, but the traffic will be plain HTTP, so we
		// use InsecureSkipVerify because this is a local connection and we
		// don't care which cert ends up being used
		var d tls.Dialer
		d.Config = &tls.Config{InsecureSkipVerify: true}
		local, err = d.DialContext(ctx, "tcp", l.ServerAddr)
	}
	if err != nil {
		_ = op.Failure(fmt.Errorf("failed to connect to server: %w", err))
		return
	}

	defer local.Close()
	cleanupLocal := context.AfterFunc(ctx, func() { _ = local.Close() })
	defer cleanupLocal()

	err = copyFull(local, remote)
	switch {
	case err == nil, errors.Is(err, errCopyDone), errors.Is(err, net.ErrClosed):
	default:
		log.Ctx(ctx).Debug().Err(err).Msg("tsrouter: proxied connection ended with error")
	}
}

func (l *tsListener) getCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certs := *l.certificates.Load()

	for _, cert := range certs {
		if chi.SupportsCertificate(&cert) == nil {
			return &cert, nil
		}
	}

	// fallback to the last cert
	if len(certs) > 0 {
		return &certs[len(certs)-1], nil
	}

	return nil, nil // certificate not found
}
