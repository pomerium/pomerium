package log

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

func decodeIfBinary(out fmt.Stringer) string {
	return out.String()
}

func TestNewHandler(t *testing.T) {
	t.Parallel()

	log := zerolog.New(nil).With().
		Str("foo", "bar").
		Logger()
	lh := NewHandler(func() *zerolog.Logger { return &log })
	h := lh(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		l := FromRequest(r)
		if !reflect.DeepEqual(*l, log) {
			t.Fail()
		}
	}))
	h.ServeHTTP(nil, &http.Request{})
}

func TestRemoteAddrHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{
		RemoteAddr: "1.2.3.4:1234",
	}
	h := RemoteAddrHandler("ip")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		l := FromRequest(r)
		l.Log().Msg("")
	}))
	log := zerolog.New(out)
	h = NewHandler(func() *zerolog.Logger { return &log })(h)
	h.ServeHTTP(nil, r)
	if want, got := `{"ip":"1.2.3.4"}`+"\n", decodeIfBinary(out); want != got {
		t.Errorf("Invalid log output, got: %s, want: %s", got, want)
	}
}

func TestRemoteAddrHandlerIPv6(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{
		RemoteAddr: "[2001:db8:a0b:12f0::1]:1234",
	}
	h := RemoteAddrHandler("ip")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		l := FromRequest(r)
		l.Log().Msg("")
	}))
	log := zerolog.New(out)
	h = NewHandler(func() *zerolog.Logger { return &log })(h)
	h.ServeHTTP(nil, r)
	if want, got := `{"ip":"2001:db8:a0b:12f0::1"}`+"\n", decodeIfBinary(out); want != got {
		t.Errorf("Invalid log output, got: %s, want: %s", got, want)
	}
}

func TestUserAgentHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{
		Header: http.Header{
			"User-Agent": []string{"some user agent string"},
		},
	}
	h := UserAgentHandler("ua")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		l := FromRequest(r)
		l.Log().Msg("")
	}))
	log := zerolog.New(out)
	h = NewHandler(func() *zerolog.Logger { return &log })(h)
	h.ServeHTTP(nil, r)
	if want, got := `{"ua":"some user agent string"}`+"\n", decodeIfBinary(out); want != got {
		t.Errorf("Invalid log output, got: %s, want: %s", got, want)
	}
}

func TestRefererHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{
		Header: http.Header{
			"Referer": []string{"http://foo.com/bar"},
		},
	}
	h := RefererHandler("referer")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		l := FromRequest(r)
		l.Log().Msg("")
	}))
	log := zerolog.New(out)
	h = NewHandler(func() *zerolog.Logger { return &log })(h)
	h.ServeHTTP(nil, r)
	if want, got := `{"referer":"http://foo.com/bar"}`+"\n", decodeIfBinary(out); want != got {
		t.Errorf("Invalid log output, got: %s, want: %s", got, want)
	}
}

func TestRequestIDHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{
		Header: http.Header{
			"X-Request-Id": []string{"1234"},
		},
	}
	h := RequestIDHandler("request-id")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		requestID := requestid.FromContext(r.Context())
		l := FromRequest(r)
		l.Log().Msg("")
		if want, got := fmt.Sprintf(`{"request-id":"%s"}`+"\n", requestID), decodeIfBinary(out); want != got {
			t.Errorf("Invalid log output, got: %s, want: %s", got, want)
		}
	}))
	log := zerolog.New(out)
	h = NewHandler(func() *zerolog.Logger { return &log })(h)
	h = requestid.HTTPMiddleware()(h)
	h.ServeHTTP(httptest.NewRecorder(), r)
}

func BenchmarkDataRace(b *testing.B) {
	log := zerolog.New(nil).With().
		Str("foo", "bar").
		Logger()
	lh := NewHandler(func() *zerolog.Logger { return &log })
	h := lh(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		l := FromRequest(r)
		l.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("bar", "baz")
		})
		l.Log().Msg("")
	}))

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			h.ServeHTTP(nil, &http.Request{})
		}
	})
}

func TestLogHeadersHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	r.Header.Set("X-Forwarded-For", "proxy1,proxy2,proxy3")

	h := HeadersHandler([]string{"X-Forwarded-For"})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		l := FromRequest(r)
		l.Log().Msg("")
	}))
	log := zerolog.New(out)
	h = NewHandler(func() *zerolog.Logger { return &log })(h)
	h.ServeHTTP(nil, r)
	if want, got := `{"X-Forwarded-For":["proxy1,proxy2,proxy3"]}`+"\n", decodeIfBinary(out); want != got {
		t.Errorf("Invalid log output, got: %s, want: %s", got, want)
	}
}

func TestAccessHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	h := AccessHandler(func(r *http.Request, status, size int, _ time.Duration) {
		l := FromRequest(r)
		l.Log().Int("status", status).Int("size", size).Msg("info")
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := FromRequest(r)
		l.Log().Msg("some inner logging")
		w.Write([]byte("Add something to the request of non-zero size"))
	}))
	log := zerolog.New(out)
	h = NewHandler(func() *zerolog.Logger { return &log })(h)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)
	want := "{\"message\":\"some inner logging\"}\n{\"status\":200,\"size\":45,\"message\":\"info\"}\n"
	got := decodeIfBinary(out)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("TestAccessHandler: %s", diff)
	}
}
