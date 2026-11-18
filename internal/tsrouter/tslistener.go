package tsrouter

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/pires/go-proxyproto"
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
	ServerAddr       string
	Insecure         bool
	UseProxyProtocol bool
	Settings         config.TailscaleListenerSettings

	telemetry      telemetry.Component
	tsRouterConfig *tsRouterConfig
	cc             *grpc.ClientConn
	certificates   atomic.Pointer[[]tls.Certificate]

	stop context.CancelCauseFunc
	wg   sync.WaitGroup
}

func newTSListener(
	tracerProvider oteltrace.TracerProvider,
	cfg *config.Config,
	settings config.TailscaleListenerSettings,
	tsRouterConfig *tsRouterConfig,
	cc *grpc.ClientConn,
	certificates []tls.Certificate,
) *tsListener {
	l := &tsListener{
		ServerAddr:       cfg.Options.Addr,
		Insecure:         cfg.Options.InsecureServer,
		UseProxyProtocol: cfg.Options.UseProxyProtocol,
		Settings:         settings,
		telemetry: *telemetry.NewComponent(tracerProvider, zerolog.DebugLevel, "tslistener",
			attribute.String("hostname", settings.Hostname.Value)),
		tsRouterConfig: tsRouterConfig,
		cc:             cc,
	}
	l.certificates.Store(&certificates)
	return l
}

func (l *tsListener) Equal(other *tsListener) bool {
	if l == nil && other == nil {
		return true
	} else if l == nil || other == nil {
		return false
	}
	return l.ServerAddr == other.ServerAddr &&
		l.Insecure == other.Insecure &&
		l.UseProxyProtocol == other.UseProxyProtocol &&
		l.cc == other.cc &&
		reflect.DeepEqual(l.Settings, other.Settings)
}

func (l *tsListener) Start(ctx context.Context) {
	_, op := l.telemetry.Start(ctx, "Start")
	defer op.Complete()

	ctx, l.stop = context.WithCancelCause(ctx)

	client := databroker.NewDataBrokerServiceClient(l.cc)

	// the actual tsnet listener is run within a lease so that only one Pomerium Proxy
	// node will handle each host
	l.runTillDone(ctx, func() error {
		return databrokerutil.NewLeasers("tslistener/"+l.Settings.Hostname.Value, 30*time.Second,
			client,
			func(ctx context.Context) error {
				return l.runLeased(ctx, client)
			}).Run(ctx)
	})
}

func (l *tsListener) Stop() {
	if l.stop != nil {
		l.stop(errStopped)
		l.wg.Wait()
	}
}

func (l *tsListener) runLeased(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	ctx, op := l.telemetry.Start(ctx, "runLeased",
		attribute.String("listen-addr", l.Settings.ListenAddr.Value),
		attribute.String("listen-funnel-addr", l.Settings.ListenFunnelAddr.Value),
		attribute.String("listen-service-name", l.Settings.ListenServiceName.Value))
	defer op.Complete()

	dir := filepath.Join(l.tsRouterConfig.directory, l.Settings.Hostname.Value)
	logger := l.telemetry.Logger(ctx)
	srv := &tsnet.Server{
		Dir:           dir,
		Store:         newTSListenerStateStore(ctx, l, client),
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
			logger.Info().Msgf(format, args...)
		},
		Logf: func(format string, args ...any) {
			logger.Debug().Msgf(format, args...)
		},
	}
	defer srv.Close()

	err := srv.Start()
	if err != nil {
		return op.Failure(fmt.Errorf("failed to start tailnet server: %w", err))
	}

	_, err = srv.Up(ctx)
	if err != nil {
		return op.Failure(fmt.Errorf("failed to connect the tailnet server: %w", err))
	}

	if l.Settings.ListenAddr.IsSet {
		log.Ctx(ctx).Info().Msg("starting tailnet listener")
		l.runTillDone(ctx, func() error {
			var li net.Listener
			var err error
			if l.Settings.TerminateTLS.Value {
				li, err = srv.ListenTLS("tcp", l.Settings.ListenAddr.Value)
			} else {
				li, err = srv.Listen("tcp", l.Settings.ListenAddr.Value)
			}
			if err != nil {
				return fmt.Errorf("failed to start tailnet listener: %w", err)
			}
			l.handleListener(ctx, li, !l.Settings.TerminateTLS.Value)
			return nil
		})
	}

	if l.Settings.ListenFunnelAddr.IsSet {
		log.Ctx(ctx).Info().Msg("starting funnel listener")
		l.runTillDone(ctx, func() error {
			funnelOptions := []tsnet.FunnelOption{tsnet.FunnelOnly()}
			if !l.Settings.TerminateTLS.Value {
				funnelOptions = append(funnelOptions, tsnet.FunnelTLSConfig(&tls.Config{
					GetCertificate: l.getCertificate,
				}))
			}
			li, err := srv.ListenFunnel("tcp", l.Settings.ListenFunnelAddr.Value, funnelOptions...)
			if err != nil {
				return fmt.Errorf("failed to start tailnet funnel listener: %w", err)
			}
			l.handleListener(ctx, li, false)
			return nil
		})
	}

	if l.Settings.ListenServiceName.IsSet {
		log.Ctx(ctx).Info().Msg("starting service listener")
		l.runTillDone(ctx, func() error {
			li, err := srv.ListenService(l.Settings.ListenServiceName.Value, tsnet.ServiceModeTCP{
				Port:         uint16(l.Settings.ListenServicePort.Value),
				TerminateTLS: l.Settings.TerminateTLS.Value,
			})
			if err != nil {
				return fmt.Errorf("error starting tailnet service listener: %w", err)
			}
			l.handleListener(ctx, li, !l.Settings.TerminateTLS.Value)
			return nil
		})
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
			l.runTillDone(ctx, func() error {
				l.handleConn(ctx, conn, rawTCP)
				return nil
			})
		} else {
			// if the reason we go an error is because the context is done, just return
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

	local, err := l.dialLocal(ctx, remote, rawTCP)
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

func (l *tsListener) dialLocal(ctx context.Context, remote net.Conn, rawTCP bool) (local net.Conn, err error) {
	if rawTCP && l.Insecure {
		return nil, fmt.Errorf("tailscale is only supported with insecure_server when TLS is terminated")
	}

	var d net.Dialer
	local, err = d.DialContext(ctx, "tcp", l.ServerAddr)
	if err != nil {
		return nil, err
	}

	if l.UseProxyProtocol {
		header := proxyproto.HeaderProxyFromAddrs(2, remote.RemoteAddr(), remote.LocalAddr())
		_, err = header.WriteTo(local)
		if err != nil {
			_ = local.Close()
			return nil, err
		}
	}

	if rawTCP || l.Insecure {
		// raw TCP: Pomerium terminates TLS, so pass the stream through.
		// insecure: Pomerium serves plain HTTP, which is what Tailscale hands us.
		return local, nil
	}

	tlsConn := tls.Client(local, &tls.Config{InsecureSkipVerify: true})
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		_ = local.Close()
		return nil, err
	}
	local = tlsConn

	return local, nil
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

func (l *tsListener) runTillDone(ctx context.Context, fn func() error) {
	b := backoff.WithContext(backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(0)), ctx)
	l.wg.Go(func() {
		_ = backoff.RetryNotify(fn, b, func(err error, d time.Duration) {
			log.Ctx(ctx).Error().Err(err).Dur("delay", d).Msg("tslistener: error performing operation")
		})
	})
}
