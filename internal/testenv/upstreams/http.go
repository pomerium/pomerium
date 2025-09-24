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
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

type Protocol string

const (
	DialHTTP1 Protocol = "http/1.1"
	DialHTTP2 Protocol = "h2"
	DialHTTP3 Protocol = "h3"
)

type RequestOptions struct {
	requestCtx     context.Context
	path           string
	query          url.Values
	headers        map[string]string
	authenticateAs string
	body           any
	clientCerts    []tls.Certificate
	clientHook     func(*http.Client) *http.Client
	dialerHook     func(*websocket.Dialer, *url.URL) (*websocket.Dialer, *url.URL)
	dialProtocol   Protocol
	trace          *httptrace.ClientTrace
}

type RequestOption func(*RequestOptions)

func (ro RequestOption) Format(fmt.State, rune) {
	panic("test bug: request option mistakenly passed to assert function")
}

func (o *RequestOptions) apply(opts ...RequestOption) {
	for _, op := range opts {
		op(o)
	}
}

// Path sets the path of the request. If omitted, the request URL will match
// the route URL exactly.
func Path(path string) RequestOption {
	return func(o *RequestOptions) {
		o.path = path
	}
}

// Query sets optional query parameters of the request.
func Query(query url.Values) RequestOption {
	return func(o *RequestOptions) {
		o.query = query
	}
}

// Headers adds optional headers to the request.
func Headers(headers map[string]string) RequestOption {
	return func(o *RequestOptions) {
		o.headers = headers
	}
}

func AuthenticateAs(email string) RequestOption {
	return func(o *RequestOptions) {
		o.authenticateAs = email
	}
}

// ClientHook allows editing or replacing the http client before it is used.
// When any request is about to start, this function will be called with the
// client that would be used to make the request. The returned client will
// be the actual client used for that request. It can be the same as the input
// (with or without modification), or replaced entirely.
//
// Note: the Transport of the client passed to the hook will always be a
// [*Transport]. That transport's underlying transport will always be
// a [*otelhttp.Transport].
func ClientHook(f func(*http.Client) *http.Client) RequestOption {
	return func(o *RequestOptions) {
		o.clientHook = f
	}
}

// DialerHook allows editing or replacing the websocket dialer before it is
// used. When a websocket request is about to start (using the DialWS method),
// this function will be called with the dialer that would be used, and the
// destination URL (including wss:// scheme, and path if one is present). The
// returned dialer+URL will be the actual dialer+URL used for that request.
//
// If ClientHook is also set, both will be called. The dialer passed to this
// hook will have its TLSClientConfig and Jar fields set from the client.
func DialerHook(f func(*websocket.Dialer, *url.URL) (*websocket.Dialer, *url.URL)) RequestOption {
	return func(o *RequestOptions) {
		o.dialerHook = f
	}
}

func DialProtocol(protocol Protocol) RequestOption {
	return func(o *RequestOptions) {
		o.dialProtocol = protocol
	}
}

func Context(ctx context.Context) RequestOption {
	return func(o *RequestOptions) {
		o.requestCtx = ctx
	}
}

func WithClientTrace(ct *httptrace.ClientTrace) RequestOption {
	return func(o *RequestOptions) {
		o.trace = ct
	}
}

// Body sets the body of the request.
// The argument can be one of the following types:
// - string
// - []byte
// - io.Reader
// - proto.Message
// - any json-encodable type
// If the argument is encoded as json, the Content-Type header will be set to
// "application/json". If the argument is a proto.Message, the Content-Type
// header will be set to "application/octet-stream".
func Body(body any) RequestOption {
	return func(o *RequestOptions) {
		o.body = body
	}
}

// ClientCert adds a client certificate to the request.
func ClientCert[T interface {
	*testenv.Certificate | *tls.Certificate
}](cert T) RequestOption {
	return func(o *RequestOptions) {
		o.clientCerts = append(o.clientCerts, *(*tls.Certificate)(cert))
	}
}

type HTTPUpstreamOptions struct {
	CommonUpstreamOptions
}

type HTTPUpstreamOption interface {
	applyHTTP(*HTTPUpstreamOptions)
}

// HTTPUpstream represents a HTTP server which can be used as the target for
// one or more Pomerium routes in a test environment.
//
// The Handle() method can be used to add handlers the server-side HTTP router,
// while the Get(), Post(), and (generic) Do() methods can be used to make
// client-side requests.
type HTTPUpstream interface {
	testenv.Upstream

	Handle(path string, f func(http.ResponseWriter, *http.Request))
	HandleWS(path string, upgrader websocket.Upgrader, f func(conn *websocket.Conn) error)
	Router() *http.ServeMux

	Get(r testenv.Route, opts ...RequestOption) (*http.Response, error)
	Post(r testenv.Route, opts ...RequestOption) (*http.Response, error)
	Do(method string, r testenv.Route, opts ...RequestOption) (*http.Response, error)
	DialWS(r testenv.Route, f func(conn *websocket.Conn) error, opts ...RequestOption) error
}

type httpUpstream struct {
	HTTPUpstreamOptions
	testenv.Aggregate
	serverPort values.MutableValue[int]
	tlsConfig  values.Value[*tls.Config]

	clientCache sync.Map // map[testenv.Route]*http.Client

	mux                  *http.ServeMux
	serverTracerProvider values.MutableValue[oteltrace.TracerProvider]
	clientTracerProvider values.MutableValue[oteltrace.TracerProvider]
	clientTracer         values.Value[oteltrace.Tracer]
}

var (
	_ testenv.Upstream = (*httpUpstream)(nil)
	_ HTTPUpstream     = (*httpUpstream)(nil)
)

// HTTP creates a new HTTP upstream server.
func HTTP(tlsConfig values.Value[*tls.Config], opts ...HTTPUpstreamOption) HTTPUpstream {
	options := HTTPUpstreamOptions{
		CommonUpstreamOptions: CommonUpstreamOptions{
			displayName: "HTTP Upstream",
		},
	}
	for _, op := range opts {
		op.applyHTTP(&options)
	}
	up := &httpUpstream{
		HTTPUpstreamOptions:  options,
		serverPort:           values.Deferred[int](),
		mux:                  http.NewServeMux(),
		tlsConfig:            tlsConfig,
		serverTracerProvider: values.Deferred[oteltrace.TracerProvider](),
		clientTracerProvider: values.Deferred[oteltrace.TracerProvider](),
	}
	up.clientTracer = values.Bind(up.clientTracerProvider, func(tp oteltrace.TracerProvider) oteltrace.Tracer {
		return tp.Tracer(trace.PomeriumCoreTracer)
	})
	up.RecordCaller()
	return up
}

// Port implements HTTPUpstream.
func (h *httpUpstream) Addr() values.Value[string] {
	return values.Bind(h.serverPort, func(port int) string {
		return fmt.Sprintf("%s:%d", h.Env().Host(), port)
	})
}

// Router implements HTTPUpstream.
func (h *httpUpstream) Handle(path string, f func(http.ResponseWriter, *http.Request)) {
	h.mux.HandleFunc(path, f)
}

func (h *httpUpstream) Router() *http.ServeMux {
	return h.mux
}

// Router implements HTTPUpstream.
func (h *httpUpstream) HandleWS(path string, upgrader websocket.Upgrader, f func(*websocket.Conn) error) {
	h.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		ctx, span := trace.Continue(r.Context(), "HandleWS")
		defer span.End()
		c, err := upgrader.Upgrade(w, r.WithContext(ctx), nil)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		defer c.Close()

		err = f(c)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			span.SetStatus(codes.Error, err.Error())
			fmt.Fprintf(os.Stderr, "websocket error: %s\n", err.Error())
		}
	})
}

// Route implements HTTPUpstream.
func (h *httpUpstream) Route() testenv.RouteStub {
	r := &testenv.PolicyRoute{}
	protocol := "http"
	r.To(values.Bind(h.serverPort, func(port int) string {
		return fmt.Sprintf("%s://%s:%d", protocol, h.Env().Host(), port)
	}))
	h.Add(r)
	return r
}

// Run implements HTTPUpstream.
func (h *httpUpstream) Run(ctx context.Context) error {
	var listener net.Listener
	if h.tlsConfig != nil {
		var err error
		listener, err = tls.Listen("tcp", fmt.Sprintf("%s:0", h.Env().Host()), h.tlsConfig.Value())
		if err != nil {
			return err
		}
	} else {
		var err error
		listener, err = net.Listen("tcp", fmt.Sprintf("%s:0", h.Env().Host()))
		if err != nil {
			return err
		}
	}
	h.serverPort.Resolve(listener.Addr().(*net.TCPAddr).Port)
	if h.serverTracerProviderOverride != nil {
		h.serverTracerProvider.Resolve(h.serverTracerProviderOverride)
	} else {
		h.serverTracerProvider.Resolve(trace.NewTracerProvider(ctx, h.displayName))
	}
	if h.clientTracerProviderOverride != nil {
		h.clientTracerProvider.Resolve(h.clientTracerProviderOverride)
	} else {
		h.clientTracerProvider.Resolve(trace.NewTracerProvider(ctx, "HTTP Client"))
	}

	server := &http.Server{}
	server.Handler = h.mux
	server.Handler = trace.NewHTTPMiddleware(otelhttp.WithTracerProvider(h.serverTracerProvider.Value()))(server.Handler)

	if h.delayShutdown {
		return snippets.RunWithDelayedShutdown(ctx,
			func() error {
				return server.Serve(listener)
			},
			func() {
				_ = server.Shutdown(context.Background())
			},
		)()
	}
	errC := make(chan error, 1)
	go func() {
		errC <- server.Serve(listener)
	}()
	select {
	case <-ctx.Done():
		_ = server.Shutdown(context.Background())
		return context.Cause(ctx)
	case err := <-errC:
		return err
	}
}

// Get implements HTTPUpstream.
func (h *httpUpstream) Get(r testenv.Route, opts ...RequestOption) (*http.Response, error) {
	return h.Do(http.MethodGet, r, opts...)
}

// Post implements HTTPUpstream.
func (h *httpUpstream) Post(r testenv.Route, opts ...RequestOption) (*http.Response, error) {
	return h.Do(http.MethodPost, r, opts...)
}

type Transport struct {
	*otelhttp.Transport
	// The underlying http.Transport instance wrapped by the otelhttp.Transport.
	Base *http.Transport
}

var _ http.RoundTripper = Transport{}

func (h *httpUpstream) newClient(options *RequestOptions) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs:      h.Env().ServerCAs(),
		Certificates: options.clientCerts,
	}
	transport.DialTLSContext = nil
	c := http.Client{
		Transport: &Transport{
			Transport: otelhttp.NewTransport(transport,
				otelhttp.WithTracerProvider(h.clientTracerProvider.Value()),
				otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
					return fmt.Sprintf("Client: %s %s", r.Method, r.URL.Path)
				}),
			),
			Base: transport,
		},
	}
	c.Jar, _ = cookiejar.New(&cookiejar.Options{})
	return &c
}

func (h *httpUpstream) getRouteClient(r testenv.Route, options *RequestOptions) *http.Client {
	span := oteltrace.SpanFromContext(options.requestCtx)
	var cachedClient any
	var ok bool
	if cachedClient, ok = h.clientCache.Load(r); !ok {
		span.AddEvent("creating new http client")
		cachedClient, _ = h.clientCache.LoadOrStore(r, h.newClient(options))
	} else {
		span.AddEvent("using cached http client")
	}
	client := cachedClient.(*http.Client)
	if options.clientHook != nil {
		client = options.clientHook(client)
	}
	return client
}

// Do implements HTTPUpstream.
func (h *httpUpstream) Do(method string, r testenv.Route, opts ...RequestOption) (*http.Response, error) {
	options := RequestOptions{
		requestCtx: h.Env().Context(),
	}
	options.apply(opts...)
	u, err := url.Parse(r.URL().Value())
	if err != nil {
		return nil, err
	}
	if options.path != "" || options.query != nil {
		u = u.ResolveReference(&url.URL{
			Path:     options.path,
			RawQuery: options.query.Encode(),
		})
	}
	ctx, span := h.clientTracer.Value().Start(options.requestCtx, "httpUpstream.Do", oteltrace.WithAttributes(
		attribute.String("method", method),
		attribute.String("url", u.String()),
	))
	if options.trace != nil {
		ctx = httptrace.WithClientTrace(ctx, options.trace)
	}
	options.requestCtx = ctx
	defer span.End()

	return doAuthenticatedRequest(options.requestCtx,
		func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, method, u.String(), nil)
		},
		func(context.Context) *http.Client {
			return h.getRouteClient(r, &options)
		},
		&options,
	)
}

func (h *httpUpstream) DialWS(r testenv.Route, f func(conn *websocket.Conn) error, opts ...RequestOption) error {
	options := RequestOptions{
		requestCtx: h.Env().Context(),
	}
	options.apply(opts...)
	u, err := url.Parse(r.URL().Value())
	if err != nil {
		return err
	}
	u.Scheme = "wss"
	if options.path != "" || options.query != nil {
		u = u.ResolveReference(&url.URL{
			Path:     options.path,
			RawQuery: options.query.Encode(),
		})
	}
	ctx, span := h.clientTracer.Value().Start(options.requestCtx, "httpUpstream.Dial", oteltrace.WithAttributes(
		attribute.String("url", u.String()),
	))
	options.requestCtx = ctx
	defer span.End()

	client := h.getRouteClient(r, &options)
	d := &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig:  client.Transport.(*Transport).Base.TLSClientConfig,
		Jar:              client.Jar,
	}
	if options.dialerHook != nil {
		d, u = options.dialerHook(d, u)
	}
	conn, resp, err := d.DialContext(options.requestCtx, u.String(), nil)
	if err != nil {
		resp.Body.Close()
		return fmt.Errorf("DialContext: %w", err)
	}
	defer conn.Close()

	return f(conn)
}
