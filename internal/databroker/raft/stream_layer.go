package raft

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"github.com/rs/zerolog"
	"github.com/volatiletech/null/v9"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/pkg/derivecert"
)

const certificateServerName = "pomerium-databroker-raft"

// errors
var (
	ErrDialerNotAvailable   = errors.New("dialer not available")
	ErrListenerNotAvailable = errors.New("listener not available")
)

// A StreamLayer implements the raft stream layer and supports dynamic config
// updates.
//
// The stream layer is implemented using TLS connections with certificates
// derived from the shared key.
type StreamLayer interface {
	raft.StreamLayer
	OnConfigChange(context.Context, *config.Config)
}

type streamLayer struct {
	telemetry telemetry.Component

	mu        sync.RWMutex
	closeCtx  context.Context
	close     context.CancelFunc
	sharedKey []byte
	bindAddr  null.String
	listener  net.Listener
	dialer    interface {
		DialContext(ctx context.Context, network string, addr string) (net.Conn, error)
	}
}

// NewStreamLayer creates a new StreamLayer.
func NewStreamLayer(tracerProvider oteltrace.TracerProvider) StreamLayer {
	l := &streamLayer{
		telemetry: *telemetry.NewComponent(tracerProvider, zerolog.TraceLevel, "raft-stream-layer"),
	}
	l.closeCtx, l.close = context.WithCancel(context.Background())
	return l
}

func (l *streamLayer) Accept() (net.Conn, error) {
	l.mu.RLock()
	li := l.listener
	l.mu.RUnlock()

	if li == nil {
		return nil, ErrListenerNotAvailable
	}

	return li.Accept()
}

func (l *streamLayer) Addr() net.Addr {
	l.mu.RLock()
	bindAddr := l.bindAddr
	l.mu.RUnlock()

	addr, err := net.ResolveTCPAddr("tcp", bindAddr.String)
	if err != nil {
		addr = &net.TCPAddr{}
	}

	return addr
}

func (l *streamLayer) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.close()

	var err error
	if l.listener != nil {
		err = l.listener.Close()
		l.listener = nil
	}

	return err
}

func (l *streamLayer) Dial(addr raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	l.mu.RLock()
	d := l.dialer
	l.mu.RUnlock()

	if d == nil {
		return nil, ErrDialerNotAvailable
	}

	ctx, clearTimeout := context.WithTimeout(l.closeCtx, timeout)
	defer clearTimeout()

	return d.DialContext(ctx, "tcp", string(addr))
}

func (l *streamLayer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	ctx, op := l.telemetry.Start(ctx, "OnConfigChange")
	defer op.Complete()

	l.mu.Lock()
	defer l.mu.Unlock()

	// make sure we haven't closed
	if l.closeCtx.Err() != nil {
		return
	}

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("invalid shared key")
	}

	bindAddr := cfg.Options.DataBroker.RaftBindAddress

	if bytes.Equal(sharedKey, l.sharedKey) &&
		l.bindAddr == bindAddr {
		// no change, so just return
		return
	}
	l.sharedKey = sharedKey
	l.bindAddr = bindAddr

	l.updateLocked(ctx)
}

func (l *streamLayer) updateLocked(ctx context.Context) {
	ctx, op := l.telemetry.Start(ctx, "Update")
	defer op.Complete()

	ca, err := derivecert.NewCA(l.sharedKey)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create certificate authority")
		return
	}

	caPEM, err := ca.PEM()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to encode certificate authority")
		return
	}

	caTLS, err := caPEM.TLS()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to convert certificate authority")
		return
	}

	certPEM, err := ca.NewServerCert([]string{certificateServerName}, func(c *x509.Certificate) {
		c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	})
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to generate certificate")
		return
	}

	certTLS, err := certPEM.TLS()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to convert certificate")
		return
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &certTLS, nil
		},
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &certTLS, nil
		},
		RootCAs:    x509.NewCertPool(),
		ServerName: certificateServerName,
	}
	tlsConfig.RootCAs.AddCert(caTLS.Leaf)

	l.listener, err = tls.Listen("tcp", l.bindAddr.String, tlsConfig)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to start tls listener")
		return
	}

	l.dialer = &tls.Dialer{
		Config: tlsConfig,
	}
}
