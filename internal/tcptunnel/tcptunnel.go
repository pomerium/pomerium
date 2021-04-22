// Package tcptunnel contains an implementation of a TCP tunnel via HTTP Connect.
package tcptunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/pomerium/pomerium/internal/authclient"
	"github.com/pomerium/pomerium/internal/cliutil"
	"github.com/pomerium/pomerium/internal/log"

	backoff "github.com/cenkalti/backoff/v4"
)

// A Tunnel represents a TCP tunnel over HTTP Connect.
type Tunnel struct {
	cfg  *config
	auth *authclient.AuthClient
}

// New creates a new Tunnel.
func New(options ...Option) *Tunnel {
	cfg := getConfig(options...)
	return &Tunnel{
		cfg:  cfg,
		auth: authclient.New(authclient.WithTLSConfig(cfg.tlsConfig)),
	}
}

// RunListener runs a network listener on the given address. For each
// incoming connection a new TCP tunnel is established via Run.
func (tun *Tunnel) RunListener(ctx context.Context, listenerAddress string) error {
	li, err := net.Listen("tcp", listenerAddress)
	if err != nil {
		return err
	}
	defer func() { _ = li.Close() }()
	log.Info(ctx).Msg("tcptunnel: listening on " + li.Addr().String())

	go func() {
		<-ctx.Done()
		_ = li.Close()
	}()

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0

	for {
		conn, err := li.Accept()
		if err != nil {
			// canceled, so ignore the error and return
			if ctx.Err() != nil {
				return nil
			}

			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				log.Warn(ctx).Err(err).Msg("tcptunnel: temporarily failed to accept local connection")
				select {
				case <-time.After(bo.NextBackOff()):
				case <-ctx.Done():
					return ctx.Err()
				}
				continue
			}
			return err
		}
		bo.Reset()

		go func() {
			defer func() { _ = conn.Close() }()

			err := tun.Run(ctx, conn)
			if err != nil {
				log.Error(ctx).Err(err).Msg("tcptunnel: error serving local connection")
			}
		}()
	}
}

// Run establishes a TCP tunnel via HTTP Connect and forwards all traffic from/to local.
func (tun *Tunnel) Run(ctx context.Context, local io.ReadWriter) error {
	rawJWT, err := tun.cfg.jwtCache.LoadJWT(tun.jwtCacheKey())
	switch {
	// if there is no error, or it is one of the pre-defined cliutil errors,
	// then ignore and use an empty JWT
	case err == nil,
		errors.Is(err, cliutil.ErrExpired),
		errors.Is(err, cliutil.ErrInvalid),
		errors.Is(err, cliutil.ErrNotFound):
	default:
		return fmt.Errorf("tcptunnel: failed to load JWT: %w", err)
	}
	return tun.run(ctx, local, rawJWT, 0)
}

func (tun *Tunnel) run(ctx context.Context, local io.ReadWriter, rawJWT string, retryCount int) error {
	log.Info(ctx).
		Str("dst", tun.cfg.dstHost).
		Str("proxy", tun.cfg.proxyHost).
		Bool("secure", tun.cfg.tlsConfig != nil).
		Msg("tcptunnel: opening connection")

	hdr := http.Header{}
	if rawJWT != "" {
		hdr.Set("Authorization", "Pomerium "+rawJWT)
	}

	req := (&http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: tun.cfg.dstHost},
		Host:   tun.cfg.dstHost,
		Header: hdr,
	}).WithContext(ctx)

	var remote net.Conn
	var err error
	if tun.cfg.tlsConfig != nil {
		remote, err = (&tls.Dialer{Config: tun.cfg.tlsConfig}).DialContext(ctx, "tcp", tun.cfg.proxyHost)
	} else {
		remote, err = (&net.Dialer{}).DialContext(ctx, "tcp", tun.cfg.proxyHost)
	}
	if err != nil {
		return fmt.Errorf("tcptunnel: failed to establish connection to proxy: %w", err)
	}
	defer func() {
		_ = remote.Close()
		log.Info(ctx).Msg("tcptunnel: connection closed")
	}()
	if done := ctx.Done(); done != nil {
		go func() {
			<-done
			_ = remote.Close()
		}()
	}

	err = req.Write(remote)
	if err != nil {
		return err
	}

	br := bufio.NewReader(remote)
	res, err := http.ReadResponse(br, req)
	if err != nil {
		return fmt.Errorf("tcptunnel: failed to read HTTP response: %w", err)
	}
	defer func() {
		_ = res.Body.Close()
	}()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect:
		if retryCount == 0 {
			_ = remote.Close()

			serverURL := &url.URL{
				Scheme: "http",
				Host:   tun.cfg.proxyHost,
			}
			if tun.cfg.tlsConfig != nil {
				serverURL.Scheme = "https"
			}

			rawJWT, err = tun.auth.GetJWT(ctx, serverURL)
			if err != nil {
				return fmt.Errorf("tcptunnel: failed to get authentication JWT: %w", err)
			}

			err = tun.cfg.jwtCache.StoreJWT(tun.jwtCacheKey(), rawJWT)
			if err != nil {
				return fmt.Errorf("tcptunnel: failed to store JWT: %w", err)
			}

			return tun.run(ctx, local, rawJWT, retryCount+1)
		}
		fallthrough
	default:
		_ = tun.cfg.jwtCache.DeleteJWT(tun.jwtCacheKey())
		return fmt.Errorf("tcptunnel: invalid http response code: %d", res.StatusCode)
	}

	log.Info(ctx).Msg("tcptunnel: connection established")

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(remote, local)
		errc <- err
	}()
	remoteReader := deBuffer(br, remote)
	go func() {
		_, err := io.Copy(local, remoteReader)
		errc <- err
	}()

	select {
	case err := <-errc:
		if err != nil {
			err = fmt.Errorf("tcptunnel: %w", err)
		}
		return err
	case <-ctx.Done():
		return nil
	}
}

func (tun *Tunnel) jwtCacheKey() string {
	return fmt.Sprintf("%s|%v", tun.cfg.proxyHost, tun.cfg.tlsConfig != nil)
}

func deBuffer(br *bufio.Reader, underlying io.Reader) io.Reader {
	if br.Buffered() == 0 {
		return underlying
	}
	return io.MultiReader(io.LimitReader(br, int64(br.Buffered())), underlying)
}
