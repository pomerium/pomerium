package envoyconfig_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/interop"
	"google.golang.org/grpc/interop/grpc_testing"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
)

func TestH2C(t *testing.T) {
	env := testenv.New(t)

	up := upstreams.GRPC(insecure.NewCredentials())
	grpc_testing.RegisterTestServiceServer(up, interop.NewTestServer())

	http := up.Route().
		From(env.SubdomainURL("grpc-http")).
		To(values.Bind(up.Addr(), func(addr string) string {
			// override the target protocol to use http://
			return fmt.Sprintf("http://%s", addr)
		})).
		Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true })

	h2c := up.Route().
		From(env.SubdomainURL("grpc-h2c")).
		Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true })

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	t.Run("h2c", func(t *testing.T) {
		t.Parallel()
		recorder := env.NewLogRecorder()

		cc := up.Dial(h2c)
		client := grpc_testing.NewTestServiceClient(cc)
		_, err := client.EmptyCall(env.Context(), &grpc_testing.Empty{})
		require.NoError(t, err)
		cc.Close()

		recorder.Match([]map[string]any{
			{
				"service":               "envoy",
				"path":                  "/grpc.testing.TestService/EmptyCall",
				"message":               "http-request",
				"response-code-details": "via_upstream",
			},
		})
	})
	t.Run("http", func(t *testing.T) {
		t.Parallel()
		recorder := env.NewLogRecorder()

		cc := up.Dial(http)
		client := grpc_testing.NewTestServiceClient(cc)
		_, err := client.UnaryCall(env.Context(), &grpc_testing.SimpleRequest{})
		require.Error(t, err)
		cc.Close()

		recorder.Match([]map[string]any{
			{
				"service":               "envoy",
				"path":                  "/grpc.testing.TestService/UnaryCall",
				"message":               "http-request",
				"response-code-details": "upstream_reset_before_response_started{protocol_error}",
			},
		})
	})
}

func TestHTTP(t *testing.T) {
	env := testenv.New(t)

	up := upstreams.HTTP(nil)
	up.Handle("/foo", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "hello world")
	})

	route := up.Route().
		From(env.SubdomainURL("http")).
		Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true })

	env.AddUpstream(up)
	env.Start()

	recorder := env.NewLogRecorder()

	resp, err := up.Get(route, upstreams.Path("/foo"))
	require.NoError(t, err)

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "hello world\n", string(data))

	recorder.Match([]map[string]any{
		{
			"service":               "envoy",
			"path":                  "/foo",
			"method":                "GET",
			"message":               "http-request",
			"response-code-details": "via_upstream",
		},
	})
}

func TestTCPTunnel(t *testing.T) {
	env := testenv.New(t, testenv.Debug())

	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "test@example.com"}}))
	up := upstreams.TCP()
	routeH1 := up.Route().
		From(env.SubdomainURL("h1")).
		PPL(`{"allow":{"and":["email":{"is":"test@example.com"}]}}`)
	routeH2 := up.Route().
		From(env.SubdomainURL("h2")).
		Policy(func(p *config.Policy) {
			p.AllowWebsockets = true
		}).
		PPL(`{"allow":{"and":["email":{"is":"test@example.com"}]}}`)

	up.Handle(func(_ context.Context, c net.Conn) error {
		c.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 8)
		n, err := c.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, string(buf[:n]), "hello")
		c.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_, err = c.Write([]byte("world"))
		require.NoError(t, err)

		return nil
	})

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	t.Run("http1", func(t *testing.T) {
		assert.NoError(t, up.Dial(routeH1, func(_ context.Context, c net.Conn) error {
			c.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, err := c.Write([]byte("hello"))
			require.NoError(t, err)

			buf := make([]byte, 8)
			c.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err := c.Read(buf)
			require.NoError(t, err)

			assert.Equal(t, string(buf[:n]), "world")
			return nil
		}, upstreams.AuthenticateAs("test@example.com"), upstreams.DialProtocol(upstreams.DialHTTP1)))
	})

	t.Run("http2", func(t *testing.T) {
		assert.NoError(t, up.Dial(routeH2, func(_ context.Context, c net.Conn) error {
			c.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, err := c.Write([]byte("hello"))
			require.NoError(t, err)

			buf := make([]byte, 8)
			c.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err := c.Read(buf)
			require.NoError(t, err)

			assert.Equal(t, string(buf[:n]), "world")
			return nil
		}, upstreams.AuthenticateAs("test@example.com"), upstreams.DialProtocol(upstreams.DialHTTP2)))
	})
}

func BenchmarkHTTP1TCPTunnel(b *testing.B) {
	env := testenv.New(b, testenv.Silent())
	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "test@example.com"}}))
	up := upstreams.TCP()
	h1 := up.Route().
		From(env.SubdomainURL("bench-h1")).
		PPL(`{"allow":{"and":["email":{"is":"test@example.com"}]}}`)

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	b.Run("http1", func(b *testing.B) {
		benchmarkTCP(b, up, h1, tcpBenchmarkParams{
			msgLen:   512,
			protocol: upstreams.DialHTTP1,
		})
	})
}

func BenchmarkHTTP2TCPTunnel(b *testing.B) {
	env := testenv.New(b, testenv.Silent())
	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "test@example.com"}}))
	up := upstreams.TCP()

	h2 := up.Route().
		From(env.SubdomainURL("bench-h2")).
		Policy(func(p *config.Policy) {
			p.AllowWebsockets = true
		}).
		PPL(`{"allow":{"and":["email":{"is":"test@example.com"}]}}`)

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	b.Run("http2", func(b *testing.B) {
		benchmarkTCP(b, up, h2, tcpBenchmarkParams{
			msgLen:   512,
			protocol: upstreams.DialHTTP2,
		})
	})
}

type tcpBenchmarkParams struct {
	msgLen   int
	protocol upstreams.Protocol
}

func benchmarkTCP(b *testing.B, up upstreams.TCPUpstream, route testenv.Route, params tcpBenchmarkParams) {
	sendMsg := func(c net.Conn, buf []byte) error {
		c.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_, err := c.Write(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
		}
		return err
	}
	recvMsg := func(c net.Conn, buf []byte) error {
		c.SetReadDeadline(time.Now().Add(1 * time.Second))
		for read := 0; read != len(buf); {
			n, err := c.Read(buf)
			read += n
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return err
			}
		}
		return nil
	}
	up.Handle(func(_ context.Context, c net.Conn) error {
		for {
			buf := make([]byte, params.msgLen)
			if err := recvMsg(c, buf[:]); err != nil {
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return err
			}
			if err := sendMsg(c, buf[:]); err != nil {
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return err
			}
		}
	})
	var threads atomic.Int32
	var requests atomic.Int32
	var bytes atomic.Int64
	start := time.Now()
	b.RunParallel(func(p *testing.PB) {
		threads.Add(1)
		require.NoError(b, up.Dial(route, func(_ context.Context, c net.Conn) error {
			buf := make([]byte, params.msgLen)
			for p.Next() {
				requests.Add(1)
				bytes.Add(int64(params.msgLen))
				require.NoError(b, sendMsg(c, buf[:]))
				require.NoError(b, recvMsg(c, buf[:]))
			}
			return nil
		}, upstreams.AuthenticateAs("test@example.com"), upstreams.DialProtocol(params.protocol)))
	})
	duration := time.Since(start)
	b.Logf("sent %d requests over %d parallel connections in %s", requests.Load(), threads.Load(), duration)
	b.Logf("throughput: %f bytes/s", float64(bytes.Load())/duration.Seconds())
}

func TestHttp1Websocket(t *testing.T) {
	env := testenv.New(t)

	up := upstreams.HTTP(nil)
	up.HandleWS("/ws", websocket.Upgrader{}, func(conn *websocket.Conn) error {
		for {
			mt, message, err := conn.ReadMessage()
			if err != nil {
				return err
			}

			// echo the message back
			err = conn.WriteMessage(mt, message)
			if err != nil {
				return err
			}
		}
	})

	route := up.Route().
		From(env.SubdomainURL("ws-test")).
		Policy(func(p *config.Policy) {
			p.AllowPublicUnauthenticatedAccess = true
			p.AllowWebsockets = true
		})

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	assert.NoError(t, up.DialWS(route, func(conn *websocket.Conn) error {
		if err := conn.SetWriteDeadline(time.Now().Add(1 * time.Second)); err != nil {
			return err
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte("hello world")); err != nil {
			return err
		}
		if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			return err
		}
		mt, bytes, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		assert.Equal(t, websocket.TextMessage, mt)
		assert.Equal(t, "hello world", string(bytes))
		return nil
	}, upstreams.Path("/ws")))
}

func TestHttp1WebsocketDenied(t *testing.T) {
	env := testenv.New(t)

	up := upstreams.HTTP(nil)
	up.HandleWS("/ws", websocket.Upgrader{}, func(conn *websocket.Conn) error {
		for {
			mt, message, err := conn.ReadMessage()
			if err != nil {
				return err
			}
			if err := conn.WriteMessage(mt, message); err != nil {
				return err
			}
		}
	})

	route := up.Route().
		From(env.SubdomainURL("ws-test-denied")).
		Policy(func(p *config.Policy) {
			p.AllowPublicUnauthenticatedAccess = true
		})

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	err := up.DialWS(route, func(_ *websocket.Conn) error { return nil }, upstreams.Path("/ws"))
	require.Error(t, err)
}

func TestClientCert(t *testing.T) {
	env := testenv.New(t)
	env.Add(scenarios.DownstreamMTLS(config.MTLSEnforcementRejectConnection))

	up := upstreams.HTTP(nil)
	up.Handle("/foo", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "hello world")
	})

	clientCert := env.NewClientCert()

	route := up.Route().
		From(env.SubdomainURL("http")).
		PPL(fmt.Sprintf(`{"allow":{"and":["client_certificate":{"fingerprint":%q}]}}`, clientCert.Fingerprint()))

	env.AddUpstream(up)
	env.Start()

	recorder := env.NewLogRecorder()

	resp, err := up.Get(route, upstreams.Path("/foo"), upstreams.ClientCert(clientCert))
	require.NoError(t, err)

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "hello world\n", string(data))

	recorder.Match([]map[string]any{
		{
			"service":               "envoy",
			"path":                  "/foo",
			"method":                "GET",
			"message":               "http-request",
			"response-code-details": "via_upstream",
			"client-certificate":    testenv.ClosedMap(clientCert.EventDict()),
		},
	})
}
