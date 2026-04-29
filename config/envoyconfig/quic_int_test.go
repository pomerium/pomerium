package envoyconfig_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestHTTP3Downstream(t *testing.T) {
	if n := runtime.GOMAXPROCS(0); n < 2 {
		t.Skipf("test requires GOMAXPROCS > 1 to exercise concurrent QUIC workers (got %d)", n)
	}
	t.Logf("envoy --concurrency will be %d", runtime.GOMAXPROCS(0))

	cases := []struct {
		name     string
		bindAddr string
	}{
		{name: "loopback_ipv4"},
		{name: "dual_stack_ipv6", bindAddr: "[::]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := testenv.New(t)

			up := upstreams.HTTP(nil)
			up.Handle("/", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("OK"))
			})
			route := up.Route().
				From(env.SubdomainURL("foo")).
				Policy(func(p *config.Policy) {
					p.AllowPublicUnauthenticatedAccess = true
				})
			env.AddUpstream(up)

			env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
				cfg.Options.CodecType = nullable.From(configpb.CodecType_CODEC_TYPE_HTTP3)
				if tc.bindAddr != "" {
					cfg.Options.Addr = fmt.Sprintf("%s:%d", tc.bindAddr, env.Ports().ProxyHTTP.Value())
				}
			}))

			env.Start()
			snippets.WaitStartupComplete(env)

			u, err := url.Parse(route.URL().Value())
			require.NoError(t, err)
			proxyUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(env.Host(), u.Port()))
			require.NoError(t, err)

			rt := &http3.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    env.ServerCAs(),
					ServerName: u.Hostname(),
					NextProtos: []string{http3.NextProtoH3},
				},
				QUICConfig: &quic.Config{
					HandshakeIdleTimeout: 5 * time.Second,
					MaxIdleTimeout:       10 * time.Second,
				},
				Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
					udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
					if err != nil {
						return nil, err
					}
					return quic.Dial(ctx, udpConn, proxyUDPAddr, tlsCfg, cfg)
				},
			}
			t.Cleanup(func() { _ = rt.Close() })

			recorder := env.NewLogRecorder()

			reqCtx, cancel := context.WithTimeout(env.Context(), 15*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
			require.NoError(t, err)

			resp, err := (&http.Client{Transport: rt}).Do(req)
			require.NoError(t, err, "HTTP/3 request failed")
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, "OK", string(body))
			require.Equal(t, "HTTP/3.0", resp.Proto)

			recorder.Match([]map[string]any{{
				"service":               "envoy",
				"message":               "http-request",
				"path":                  "/",
				"response-code-details": "via_upstream",
			}})
		})
	}
}
