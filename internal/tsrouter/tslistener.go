package tsrouter

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"tailscale.com/tsnet"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

var errStopped = errors.New("stopped")

type tsListener struct {
	ServerAddr   string
	OutboundPort string
	SignedJWTKey []byte
	Settings     config.TailscaleListenerSettings

	telemetry    telemetry.Component
	certificates atomic.Pointer[[]tls.Certificate]
	tempDir      string

	stop context.CancelCauseFunc
	wg   sync.WaitGroup
}

func newTSListener(tracerProvider oteltrace.TracerProvider, cfg *config.Config, settings config.TailscaleListenerSettings) (*tsListener, error) {
	l := &tsListener{
		telemetry: *telemetry.NewComponent(tracerProvider, zerolog.InfoLevel, "tslistener",
			attribute.String("hostname", settings.Hostname.Value)),
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
		l.OutboundPort == other.OutboundPort &&
		bytes.Equal(l.SignedJWTKey, other.SignedJWTKey) &&
		reflect.DeepEqual(l.Settings, other.Settings)
}

func (l *tsListener) Start(ctx context.Context) {
	_, op := l.telemetry.Start(ctx, "Start")
	defer op.Complete()

	ctx, l.stop = context.WithCancelCause(ctx)

	cc, err := grpc.NewOutboundGRPCClientConn(ctx, &grpc.OutboundOptions{
		OutboundPort: l.OutboundPort,
		SignedJWTKey: l.SignedJWTKey,
	})
	if err != nil {
		_ = op.Failure(fmt.Errorf("failed to create outbound grpc connection: %w", err))
		return
	}
	client := databrokerpb.NewDataBrokerServiceClient(cc)

	// the actual tsnet listener is run within a lease so that only one Pomerium Proxy
	// node will handle each host
	l.wg.Go(func() {
		_ = databrokerutil.NewLeasers("tslistener/"+l.Settings.Hostname.Value, 30*time.Second, client,
			func(ctx context.Context) error {
				l.startLeased(ctx, client)
				<-ctx.Done()
				return context.Cause(ctx)
			}).Run(ctx)
	})
}

func (l *tsListener) Stop() {
	if l.stop != nil {
		log.Info().Msg("tsrouter: stopping listener")
		l.stop(errStopped)
		l.wg.Wait()

		_ = os.RemoveAll(l.tempDir)
	}
}

func (l *tsListener) init(cfg *config.Config, settings config.TailscaleListenerSettings) error {
	_, op := l.telemetry.Start(context.Background(), "init")
	defer op.Complete()

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return op.Failure(fmt.Errorf("error getting shared key: %w", err))
	}

	l.ServerAddr = cfg.Options.Addr
	l.OutboundPort = cfg.OutboundPort
	l.SignedJWTKey = sharedKey
	l.Settings = settings

	certs, err := cfg.AllCertificates()
	if err != nil {
		return op.Failure(fmt.Errorf("error loading certificates: %w", err))
	}

	catchAll, err := cfg.GenerateCatchAllCertificate()
	if err != nil {
		return op.Failure(fmt.Errorf("error generating catch-all certificate: %w", err))
	}

	l.certificates.Store(new(append(slices.Clone(certs), *catchAll)))

	l.tempDir, err = os.MkdirTemp("", "tslistener-*")
	if err != nil {
		return op.Failure(fmt.Errorf("error making temporary directory: %w", err))
	}

	return nil
}

func (l *tsListener) startLeased(ctx context.Context, client databrokerpb.DataBrokerServiceClient) {
	opCtx, op := l.telemetry.Start(ctx, "startLeased",
		attribute.String("listen-addr", l.Settings.ListenAddr.Value),
		attribute.String("listen-funnel-addr", l.Settings.ListenFunnelAddr.Value),
		attribute.String("listen-service-name", l.Settings.ListenServiceName.Value))
	defer op.Complete()

	log.Ctx(opCtx).Info().Msg("tsrouter: starting listener")

	l.wg.Go(func() {
		databrokerutil.NewDirectoryMirror(client, "tslistener/"+l.Settings.Hostname.Value, l.tempDir).Watch(ctx)
	})

	srv := &tsnet.Server{
		Dir:           l.tempDir,
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
			_ = op.Failure(fmt.Errorf("failed to start tailnet listener: %w", err))
			return
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
			_ = op.Failure(fmt.Errorf("failed to start tailnet funnel listener: %w", err))
		} else {
			l.wg.Go(func() { l.handleListener(ctx, li, false) })
		}
	}

	if l.Settings.ListenServiceName.IsSet {
		log.Ctx(opCtx).Info().Msg("starting service listener")
		li, err := srv.ListenService(l.Settings.ListenServiceName.Value, tsnet.ServiceModeTCP{
			Port:         uint16(l.Settings.ListenServicePort.Value),
			TerminateTLS: l.Settings.TerminateTLS.Value,
		})
		if err != nil {
			_ = op.Failure(fmt.Errorf("failed to start tailnet service listener: %w", err))
		} else {
			l.wg.Go(func() { l.handleListener(ctx, li, !l.Settings.TerminateTLS.Value) })
		}
	}
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
		_ = op.Failure(fmt.Errorf("failed to connect to server: %w", err))
		return
	}

	defer local.Close()
	cleanupLocal := context.AfterFunc(ctx, func() { _ = local.Close() })
	defer cleanupLocal()

	eg, _ := errgroup.WithContext(ctx)
	eg.Go(func() error { _, err := io.Copy(local, remote); return err })
	eg.Go(func() error { _, err := io.Copy(remote, local); return err })
	err = eg.Wait()
	if err != nil {
		_ = op.Failure(fmt.Errorf("failed to proxy data: %w", err))
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
