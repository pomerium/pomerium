// Package autocache implements a key value store (kv.Store) using autocache
// which combines functionality from groupcache, and memberlist libraries.
// For more details, see https://github.com/pomerium/autocache
package autocache

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"
	"sync"

	"github.com/golang/groupcache"

	"github.com/pomerium/autocache"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/kv"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// Name represents autocache's shorthand named.
const Name = "autocache"

const defaultQueryParamKey = "ati"

var _ kv.Store = &Store{}

// Store implements a the store interface for autocache, a distributed cache
// with gossip based peer membership enrollment.
// https://github.com/pomerium/autocache
type Store struct {
	db        *groupcache.Group
	cluster   *autocache.Autocache
	sharedKey string
	srv       *http.Server
}

// ErrCacheMiss is returned when the cache misses for a given key.
var ErrCacheMiss = errors.New("cache miss")

// Options represent autocache options.
type Options struct {
	Addr          string
	CacheSize     int64
	ClusterDomain string
	GetterFn      groupcache.GetterFunc
	Group         string
	Log           *stdlog.Logger
	Port          int
	Scheme        string
	SharedKey     string
}

// DefaultOptions are the default options used by the autocache service.
var DefaultOptions = &Options{
	Addr:      ":8333",
	Port:      8333,
	Scheme:    "http",
	CacheSize: 10 << 20,
	Group:     "default",
	GetterFn: func(ctx context.Context, id string, dest groupcache.Sink) error {
		b := fromContext(ctx)
		if len(b) == 0 {
			return fmt.Errorf("autocache: id %s : %w", id, ErrCacheMiss)
		}
		if err := dest.SetBytes(b); err != nil {
			return fmt.Errorf("autocache: sink error %w", err)
		}
		return nil
	},
}

// New creates a new autocache key value store. Autocache will start several
// services to support distributed cluster management and membership.
// A HTTP server will be used by groupcache to perform cross node-RPC. By
// default that server will start on port ``:8333`.
// Memberlist will likewise start and listen for group membership on port
//
//
// NOTE: RPC communication between nodes is _authenticated_ but not encrypted.
// NOTE: Groupchache starts a HTTP listener (Default: :8333)
// NOTE: Memberlist starts a GOSSIP listener on TCP/UDP. (Default: :7946)
func New(o *Options) (*Store, error) {
	var s Store
	var err error
	if o.SharedKey == "" {
		return nil, errors.New("autocache: shared secret must be set")
	}
	if o.Addr == "" {
		o.Addr = DefaultOptions.Addr
	}
	if o.Scheme == "" {
		o.Scheme = DefaultOptions.Scheme
	}
	if o.Port == 0 {
		o.Port = DefaultOptions.Port
	}
	if o.Group == "" {
		o.Group = DefaultOptions.Group
	}
	if o.GetterFn == nil {
		o.GetterFn = DefaultOptions.GetterFn
	}
	if o.CacheSize == 0 {
		o.CacheSize = DefaultOptions.CacheSize
	}
	if o.ClusterDomain == "" {
		o.Log.Println("")
	}
	s.db = groupcache.NewGroup(o.Group, o.CacheSize, o.GetterFn)
	s.cluster, err = autocache.New(&autocache.Options{
		PoolTransportFn: s.addSessionToCtx,
		PoolScheme:      o.Scheme,
		PoolPort:        o.Port,
		Logger:          o.Log,
	})
	if err != nil {
		return nil, err
	}
	serverOpts := &httputil.ServerOptions{Addr: o.Addr, Insecure: true, Service: Name}
	var wg sync.WaitGroup
	s.srv, err = httputil.NewServer(serverOpts, metrics.HTTPMetricsHandler("groupcache")(QueryParamToCtx(s.cluster)), &wg)
	if err != nil {
		return nil, err
	}
	if _, err := s.cluster.Join([]string{o.ClusterDomain}); err != nil {
		return nil, err
	}
	metrics.AddGroupCacheMetrics(s.db)
	return &s, nil
}

// Set stores a key value pair. Since group cache actually only implements
// Get, we have to be a little creative in how we smuggle in value using
// context.
func (s Store) Set(ctx context.Context, k string, v []byte) error {
	// smuggle the value pair as a context value
	ctx = newContext(ctx, v)
	if err := s.db.Get(ctx, k, groupcache.AllocatingByteSliceSink(&v)); err != nil {
		return fmt.Errorf("autocache: set %s failed: %w", k, err)
	}
	return nil
}

// Get retrieves the value for a key in the bucket.
func (s *Store) Get(ctx context.Context, k string) (bool, []byte, error) {
	var value []byte
	if err := s.db.Get(ctx, k, groupcache.AllocatingByteSliceSink(&value)); err != nil {
		return false, nil, fmt.Errorf("autocache: get %s failed: %w", k, err)
	}
	return true, value, nil
}

// Close shuts down any HTTP server used for groupcache pool, and
// also stop any background maintenance of memberlist.
func (s Store) Close(ctx context.Context) error {
	var retErr error
	if s.srv != nil {
		if err := s.srv.Shutdown(ctx); err != nil {
			retErr = fmt.Errorf("autocache: http shutdown error: %w", err)
		}
	}
	if s.cluster.Memberlist != nil {
		if err := s.cluster.Memberlist.Shutdown(); err != nil {
			retErr = fmt.Errorf("autocache: memberlist shutdown error: %w", err)
		}
	}
	return retErr
}

// addSessionToCtx is a wrapper function that allows us to add a session
// into http client's round trip and sign the outgoing request.
func (s *Store) addSessionToCtx(ctx context.Context) http.RoundTripper {
	var sh signedSession
	sh.session = string(fromContext(ctx))
	sh.sharedKey = s.sharedKey
	return sh
}

type signedSession struct {
	session   string
	sharedKey string
}

// RoundTrip copies the request's session context and adds it to the
// outgoing client request as a query param. The whole URL is then signed for
// authenticity.
func (s signedSession) RoundTrip(req *http.Request) (*http.Response, error) {
	// clone request before mutating
	// https://golang.org/src/net/http/client.go?s=4306:5535#L105
	newReq := cloneRequest(req)
	session := s.session
	newReqURL := *newReq.URL
	q := newReqURL.Query()
	q.Set(defaultQueryParamKey, session)
	newReqURL.RawQuery = q.Encode()
	newReq.URL = urlutil.NewSignedURL(s.sharedKey, &newReqURL).Sign()

	tripper := metrics.HTTPMetricsRoundTripper("cache", "groupcache")(http.DefaultTransport)
	return tripper.RoundTrip(newReq)
}

// QueryParamToCtx takes a value from a query param and adds it to the
// current request request context.
func QueryParamToCtx(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := r.FormValue(defaultQueryParamKey)
		ctx := newContext(r.Context(), []byte(session))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

var sessionCtxKey = &contextKey{"PomeriumCachedSessionBytes"}

type contextKey struct {
	name string
}

func newContext(ctx context.Context, b []byte) context.Context {
	ctx = context.WithValue(ctx, sessionCtxKey, b)
	return ctx
}

func fromContext(ctx context.Context) []byte {
	b, _ := ctx.Value(sessionCtxKey).([]byte)
	return b
}

func cloneRequest(req *http.Request) *http.Request {
	r := new(http.Request)
	*r = *req
	r.Header = cloneHeaders(req.Header)
	return r
}

func cloneHeaders(in http.Header) http.Header {
	out := make(http.Header, len(in))
	for key, values := range in {
		newValues := make([]string, len(values))
		copy(newValues, values)
		out[key] = newValues
	}
	return out
}
