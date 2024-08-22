package upstreams

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/pomerium/pomerium/integration/forms"
	"github.com/pomerium/pomerium/internal/retry"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"google.golang.org/protobuf/proto"
)

type RequestOptions struct {
	path           string
	query          url.Values
	headers        map[string]string
	authenticateAs string
	body           any
	clientCerts    []tls.Certificate
	client         *http.Client
}

type RequestOption func(*RequestOptions)

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

func Client(c *http.Client) RequestOption {
	return func(o *RequestOptions) {
		o.client = c
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

// HTTPUpstream represents a HTTP server which can be used as the target for
// one or more Pomerium routes in a test environment.
//
// The Handle() method can be used to add handlers the server-side HTTP router,
// while the Get(), Post(), and (generic) Do() methods can be used to make
// client-side requests.
type HTTPUpstream interface {
	testenv.Upstream

	Handle(path string, f func(http.ResponseWriter, *http.Request)) *mux.Route

	Get(r testenv.Route, opts ...RequestOption) (*http.Response, error)
	Post(r testenv.Route, opts ...RequestOption) (*http.Response, error)
	Do(method string, r testenv.Route, opts ...RequestOption) (*http.Response, error)
}

type httpUpstream struct {
	testenv.Aggregate
	serverPort values.MutableValue[int]
	tlsConfig  values.Value[*tls.Config]

	clientCache sync.Map // map[testenv.Route]*http.Client

	router *mux.Router
}

var (
	_ testenv.Upstream = (*httpUpstream)(nil)
	_ HTTPUpstream     = (*httpUpstream)(nil)
)

// HTTP creates a new HTTP upstream server.
func HTTP(tlsConfig values.Value[*tls.Config]) HTTPUpstream {
	up := &httpUpstream{
		serverPort: values.Deferred[int](),
		router:     mux.NewRouter(),
		tlsConfig:  tlsConfig,
	}
	up.RecordCaller()
	return up
}

// Port implements HTTPUpstream.
func (h *httpUpstream) Port() values.Value[int] {
	return h.serverPort
}

// Router implements HTTPUpstream.
func (h *httpUpstream) Handle(path string, f func(http.ResponseWriter, *http.Request)) *mux.Route {
	return h.router.HandleFunc(path, f)
}

// Route implements HTTPUpstream.
func (h *httpUpstream) Route() testenv.RouteStub {
	r := &testenv.PolicyRoute{}
	protocol := "http"
	r.To(values.Bind(h.serverPort, func(port int) string {
		return fmt.Sprintf("%s://127.0.0.1:%d", protocol, port)
	}))
	h.Add(r)
	return r
}

// Run implements HTTPUpstream.
func (h *httpUpstream) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	h.serverPort.Resolve(listener.Addr().(*net.TCPAddr).Port)
	var tlsConfig *tls.Config
	if h.tlsConfig != nil {
		tlsConfig = h.tlsConfig.Value()
	}
	server := &http.Server{
		Handler:   h.router,
		TLSConfig: tlsConfig,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	errC := make(chan error, 1)
	go func() {
		errC <- server.Serve(listener)
	}()
	select {
	case <-ctx.Done():
		server.Close()
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

// Do implements HTTPUpstream.
func (h *httpUpstream) Do(method string, r testenv.Route, opts ...RequestOption) (*http.Response, error) {
	options := RequestOptions{}
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
	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	switch body := options.body.(type) {
	case string:
		req.Body = io.NopCloser(strings.NewReader(body))
	case []byte:
		req.Body = io.NopCloser(bytes.NewReader(body))
	case io.Reader:
		req.Body = io.NopCloser(body)
	case proto.Message:
		buf, err := proto.Marshal(body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(buf))
		req.Header.Set("Content-Type", "application/octet-stream")
	default:
		buf, err := json.Marshal(body)
		if err != nil {
			panic(fmt.Sprintf("unsupported body type: %T", body))
		}
		req.Body = io.NopCloser(bytes.NewReader(buf))
		req.Header.Set("Content-Type", "application/json")
	case nil:
	}

	newClient := func() *http.Client {
		c := http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      h.Env().ServerCAs(),
					Certificates: options.clientCerts,
				},
			},
		}
		c.Jar, _ = cookiejar.New(&cookiejar.Options{})
		return &c
	}
	var client *http.Client
	if options.client != nil {
		client = options.client
	} else {
		var cachedClient any
		var ok bool
		if cachedClient, ok = h.clientCache.Load(r); !ok {
			cachedClient, _ = h.clientCache.LoadOrStore(r, newClient())
		}
		client = cachedClient.(*http.Client)
	}

	var resp *http.Response
	if err := retry.Retry(h.Env().Context(), "http", func(ctx context.Context) error {
		var err error
		if options.authenticateAs != "" {
			resp, err = authenticateFlow(ctx, client, req, options.authenticateAs)
		} else {
			resp, err = client.Do(req)
		}
		// retry on connection refused
		if err != nil {
			var opErr *net.OpError
			if errors.As(err, &opErr) && opErr.Op == "dial" && opErr.Err.Error() == "connect: connection refused" {
				return err
			}
			return retry.NewTerminalError(err)
		}
		if resp.StatusCode == 500 {
			return errors.New("Internal Server Error")
		}
		return nil
	}, retry.WithMaxInterval(100*time.Millisecond)); err != nil {
		return nil, err
	}
	return resp, nil
}

func authenticateFlow(ctx context.Context, client *http.Client, req *http.Request, email string) (*http.Response, error) {
	var res *http.Response
	originalHostname := req.URL.Hostname()
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	location := res.Request.URL
	if location.Hostname() == originalHostname {
		// already authenticated
		return res, err
	}
	defer res.Body.Close()
	fs := forms.Parse(res.Body)
	if len(fs) > 0 {
		f := fs[0]
		f.Inputs["email"] = email
		f.Inputs["token_expiration"] = strconv.Itoa(int((time.Hour * 24).Seconds()))
		formReq, err := f.NewRequestWithContext(ctx, location)
		if err != nil {
			return nil, err
		}
		return client.Do(formReq)
	} else {
		return nil, fmt.Errorf("test bug: expected IDP login form")
	}
}
