package upstreams

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http2"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/pkg/netutil"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

type TCPUpstream interface {
	testenv.Upstream

	Handle(fn func(context.Context, net.Conn) error)

	Dial(r testenv.Route, fn func(context.Context, net.Conn) error, opts ...RequestOption) error
}

type TCPUpstreamOptions struct {
	CommonUpstreamOptions
}

type TCPUpstreamOption interface {
	applyTCP(*TCPUpstreamOptions)
}

type tcpUpstream struct {
	TCPUpstreamOptions
	testenv.Aggregate
	serverAddr    values.MutableValue[netip.AddrPort]
	serverHandler func(context.Context, net.Conn) error

	serverTracerProvider values.MutableValue[oteltrace.TracerProvider]
	clientTracerProvider values.MutableValue[oteltrace.TracerProvider]
	clientTracer         values.Value[oteltrace.Tracer]
}

func TCP(opts ...TCPUpstreamOption) TCPUpstream {
	options := TCPUpstreamOptions{
		CommonUpstreamOptions: CommonUpstreamOptions{
			displayName: "TCP Upstream",
		},
	}
	for _, op := range opts {
		op.applyTCP(&options)
	}
	up := &tcpUpstream{
		TCPUpstreamOptions: options,
		serverAddr:         values.Deferred[netip.AddrPort](),

		serverTracerProvider: values.Deferred[oteltrace.TracerProvider](),
		clientTracerProvider: values.Deferred[oteltrace.TracerProvider](),
	}
	up.clientTracer = values.Bind(up.clientTracerProvider, func(tp oteltrace.TracerProvider) oteltrace.Tracer {
		return tp.Tracer(trace.PomeriumCoreTracer)
	})
	up.RecordCaller()
	return up
}

// Dial implements TCPUpstream.
func (t *tcpUpstream) Dial(r testenv.Route, clientHandler func(context.Context, net.Conn) error, opts ...RequestOption) error {
	options := RequestOptions{
		requestCtx:   t.Env().Context(),
		dialProtocol: DialHTTP1,
	}
	options.apply(opts...)
	u, err := url.Parse(r.URL().Value())
	if err != nil {
		return err
	}

	ctx, span := t.clientTracer.Value().Start(options.requestCtx, "tcpUpstream.Do", oteltrace.WithAttributes(
		attribute.String("protocol", string(options.dialProtocol)),
		attribute.String("url", u.String()),
	))
	if options.path != "" || options.query != nil {
		u = u.ResolveReference(&url.URL{
			Path:     options.path,
			RawQuery: options.query.Encode(),
		})
	}
	if options.trace != nil {
		ctx = httptrace.WithClientTrace(ctx, options.trace)
	}
	options.requestCtx = ctx
	defer span.End()

	var remoteConn *tls.Conn
	remoteWriter := make(chan *io.PipeWriter, 1)

	connectURL := &url.URL{Scheme: "https", Host: u.Host, Path: u.Path}

	var getClientFn func(context.Context) *http.Client
	var newRequestFn func(ctx context.Context) (*http.Request, error)
	switch options.dialProtocol {
	case DialHTTP1:
		getClientFn = t.h1Dialer(&options, connectURL, &remoteConn)
		newRequestFn = func(ctx context.Context) (*http.Request, error) {
			req := (&http.Request{
				Method: http.MethodConnect,
				URL:    connectURL,
				Host:   u.Host,
			}).WithContext(ctx)
			return req, nil
		}
	case DialHTTP2:
		getClientFn = t.h2Dialer(&options, connectURL, &remoteConn, remoteWriter)
		newRequestFn = func(ctx context.Context) (*http.Request, error) {
			req := (&http.Request{
				Method: http.MethodConnect,
				URL:    connectURL,
				Host:   u.Host,
				Proto:  "HTTP/2",
			}).WithContext(ctx)
			return req, nil
		}
	case DialHTTP3:
		panic("not implemented")
	}
	resp, err := doAuthenticatedRequest(options.requestCtx, newRequestFn, getClientFn, &options)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return errors.New(resp.Status)
	}
	if resp.Request.URL.Path == "/oidc/auth" {
		if options.authenticateAs == "" {
			return errors.New("test bug: unexpected IDP redirect; missing AuthenticateAs option to Dial()")
		}
		return errors.New("internal test bug: unexpected IDP redirect")
	}

	var w io.WriteCloser = remoteConn
	if options.dialProtocol == DialHTTP2 {
		w = <-remoteWriter
	}

	conn := NewRWConn(resp.Body, w)
	defer conn.Close()
	return clientHandler(resp.Request.Context(), conn)
}

func (t *tcpUpstream) h1Dialer(
	options *RequestOptions,
	connectURL *url.URL,
	remoteConn **tls.Conn,
) func(context.Context) *http.Client {
	jar, _ := cookiejar.New(nil)
	return func(context.Context) *http.Client {
		tlsConfig := &tls.Config{
			RootCAs:      t.Env().ServerCAs(),
			Certificates: options.clientCerts,
			NextProtos:   []string{"http/1.1"},
		}
		client := &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if *remoteConn != nil {
						(*remoteConn).Close()
						*remoteConn = nil
					}
					dialer := &tls.Dialer{
						Config: tlsConfig,
					}
					cc, err := dialer.DialContext(ctx, network, addr)
					if err != nil {
						return nil, fmt.Errorf("%w: %w", ErrRetry, err)
					}
					protocol := cc.(*tls.Conn).ConnectionState().NegotiatedProtocol
					if protocol != "http/1.1" {
						cc.Close()
						return nil, fmt.Errorf("error: unexpected TLS protocol: %s", protocol)
					}
					*remoteConn = cc.(*tls.Conn)
					return cc, nil
				},
				TLSClientConfig: tlsConfig, // important
			},
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				if req.URL.String() == connectURL.String() && req.Method == http.MethodGet {
					req.Method = http.MethodConnect
				}
				return nil
			},
			Jar: jar,
		}
		return client
	}
}

func (t *tcpUpstream) h2Dialer(
	options *RequestOptions,
	connectURL *url.URL,
	remoteConn **tls.Conn,
	writer chan<- *io.PipeWriter,
) func(context.Context) *http.Client {
	jar, _ := cookiejar.New(nil)
	return func(context.Context) *http.Client {
		h1 := &http.Transport{
			ForceAttemptHTTP2: true,
			DisableKeepAlives: true,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if *remoteConn != nil {
					(*remoteConn).Close()
					*remoteConn = nil
				}
				dialer := &tls.Dialer{
					Config: &tls.Config{
						RootCAs:      t.Env().ServerCAs(),
						Certificates: options.clientCerts,
						NextProtos:   []string{"h2"},
					},
				}
				cc, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, fmt.Errorf("%w: %w", ErrRetry, err)
				}
				protocol := cc.(*tls.Conn).ConnectionState().NegotiatedProtocol
				if protocol != "h2" {
					cc.Close()
					return nil, fmt.Errorf("error: unexpected TLS protocol: %s", protocol)
				}
				*remoteConn = cc.(*tls.Conn)

				return cc, nil
			},
			TLSClientConfig: &tls.Config{
				RootCAs:      t.Env().ServerCAs(),
				Certificates: options.clientCerts,
				NextProtos:   []string{"h2"},
			},
		}
		if err := http2.ConfigureTransport(h1); err != nil {
			panic(err)
		}
		client := &http.Client{
			Transport: h1,
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				if req.URL.String() == connectURL.String() && req.Method == http.MethodGet {
					pr, pw := io.Pipe()
					req.Method = http.MethodConnect
					req.Body = pr
					req.ContentLength = -1
					writer <- pw
				}
				return nil
			},
			Jar: jar,
		}
		return client
	}
}

// Handle implements TCPUpstream.
func (t *tcpUpstream) Handle(fn func(context.Context, net.Conn) error) {
	t.serverHandler = fn
}

// Port implements TCPUpstream.
func (t *tcpUpstream) Addr() values.Value[string] {
	return values.Bind(t.serverAddr, func(addr netip.AddrPort) string {
		return addr.String()
	})
}

// Route implements TCPUpstream.
func (t *tcpUpstream) Route() testenv.RouteStub {
	r := &testenv.TCPRoute{}
	r.To(values.Bind(t.serverAddr, func(addr netip.AddrPort) string {
		return fmt.Sprintf("tcp://%s", addr.String())
	}))
	t.Add(r)
	return r
}

// Run implements TCPUpstream.
func (t *tcpUpstream) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	addrs, err := netutil.AllocateAddresses(1)
	if err != nil {
		return err
	}
	addr := addrs[0]

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr.String())
	if err != nil {
		return err
	}
	context.AfterFunc(ctx, func() {
		listener.Close()
	})
	t.serverAddr.Resolve(netip.MustParseAddrPort(listener.Addr().String()))
	if t.serverTracerProviderOverride != nil {
		t.serverTracerProvider.Resolve(t.serverTracerProviderOverride)
	} else {
		t.serverTracerProvider.Resolve(trace.NewTracerProvider(ctx, t.displayName))
	}
	if t.clientTracerProviderOverride != nil {
		t.clientTracerProvider.Resolve(t.clientTracerProviderOverride)
	} else {
		t.clientTracerProvider.Resolve(trace.NewTracerProvider(ctx, "TCP Client"))
	}
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				cancel()
				return nil
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := t.serverHandler(ctx, conn); err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				panic("server handler error: " + err.Error())
			}
		}()
	}
}

var (
	_ testenv.Upstream = (*tcpUpstream)(nil)
	_ TCPUpstream      = (*tcpUpstream)(nil)
)
