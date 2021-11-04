package tcptunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTunnel(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = backend.Close() }()

	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()

				ln, _, _ := bufio.NewReader(conn).ReadLine()
				assert.Equal(t, "HELLO WORLD", string(ln))
			}()
		}
	}()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !assert.Equal(t, "CONNECT", r.Method) {
			return
		}
		if !assert.Equal(t, "example.com:9999", r.RequestURI) {
			return
		}

		w.WriteHeader(200)

		in, brw, err := w.(http.Hijacker).Hijack()
		if !assert.NoError(t, err) {
			return
		}
		defer func() { _ = in.Close() }()

		out, err := net.Dial("tcp", backend.Addr().String())
		if !assert.NoError(t, err) {
			return
		}
		defer func() { _ = out.Close() }()

		errc := make(chan error, 2)
		go func() {
			_, err := io.Copy(in, out)
			errc <- err
		}()
		go func() {
			_, err := io.Copy(out, deBuffer(brw.Reader, in))
			errc <- err
		}()
		<-errc
	}))
	defer srv.Close()

	var buf bytes.Buffer
	tun := New(
		WithDestinationHost("example.com:9999"),
		WithProxyHost(srv.Listener.Addr().String()))
	err = tun.Run(ctx, readWriter{strings.NewReader("HELLO WORLD\n"), &buf}, DiscardEvents())
	if !assert.NoError(t, err) {
		return
	}
}

type readWriter struct {
	io.Reader
	io.Writer
}

func TestForceHTTP1(t *testing.T) {
	tunnel := New(WithTLSConfig(&tls.Config{
		InsecureSkipVerify: true,
	}))

	var protocol string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protocol = r.Proto
	}))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tunnel.cfg.tlsConfig,
		},
	}
	_, _ = client.Get(srv.URL)

	assert.Equal(t, "HTTP/1.1", protocol)
}
