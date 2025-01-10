package config

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

func Test_NewTracingOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    *Options
		want    *TracingOptions
		wantErr bool
	}{
		{
			"datadog_good",
			&Options{TracingProvider: "datadog"},
			&TracingOptions{Provider: "datadog", Service: "pomerium", SampleRate: 1},
			false,
		},
		{
			"jaeger_good",
			&Options{TracingProvider: "jaeger", TracingJaegerAgentEndpoint: "foo", TracingJaegerCollectorEndpoint: "http://foo", Services: ServiceAll},
			&TracingOptions{Provider: "jaeger", JaegerAgentEndpoint: "foo", JaegerCollectorEndpoint: &url.URL{Scheme: "http", Host: "foo"}, Service: "pomerium", SampleRate: 1},
			false,
		},
		{
			"jaeger_bad",
			&Options{TracingProvider: "jaeger", TracingJaegerAgentEndpoint: "foo", TracingJaegerCollectorEndpoint: "badurl"},
			nil,
			true,
		},
		{
			"zipkin_good",
			&Options{TracingProvider: "zipkin", ZipkinEndpoint: "https://foo/api/v1/spans", Services: ServiceAuthorize},
			&TracingOptions{Provider: "zipkin", ZipkinEndpoint: &url.URL{Scheme: "https", Host: "foo", Path: "/api/v1/spans"}, Service: "pomerium-authorize", SampleRate: 1},
			false,
		},
		{
			"zipkin_bad",
			&Options{TracingProvider: "zipkin", ZipkinEndpoint: "notaurl"},
			nil,
			true,
		},
		{
			"noprovider",
			&Options{},
			&TracingOptions{},
			false,
		},
		{
			"fakeprovider",
			&Options{TracingProvider: "fake"},
			nil,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewTracingOptions(tt.opts)
			assert.NotEqual(t, err == nil, tt.wantErr, "unexpected error value")
			assert.Empty(t, cmp.Diff(tt.want, got))
		})
	}
}

func Test_TracingEnabled(t *testing.T) {
	tests := []struct {
		name string
		opts *TracingOptions
		want bool
	}{
		{"enabled", &TracingOptions{Provider: "zipkin"}, true},
		{"not enabled", &TracingOptions{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.opts.Enabled(), "unexpected tracing state")
		})
	}
}

func TestTraceManager(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*30)
	defer clearTimeout()

	type Request struct {
		URL  string
		Name string
	}

	incoming := make(chan Request, 100)

	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var objs []struct {
			Name string
		}
		json.NewDecoder(r.Body).Decode(&objs)
		for _, obj := range objs {
			incoming <- Request{Name: obj.Name, URL: r.Host}
		}
	})

	srv1 := httptest.NewServer(h)
	defer srv1.Close()
	srv2 := httptest.NewServer(h)
	defer srv2.Close()

	src := NewStaticSource(&Config{Options: &Options{
		TracingProvider: "zipkin",
		ZipkinEndpoint:  srv1.URL,
	}})

	_ = NewTraceManager(ctx, src)

	_, span := trace.StartSpan(ctx, "Example")
	span.End()

	src.SetConfig(ctx, &Config{Options: &Options{
		TracingProvider: "zipkin",
		ZipkinEndpoint:  srv2.URL,
	}})

	_, span = trace.StartSpan(ctx, "Example")
	span.End()

	expect := map[Request]struct{}{
		{Name: "example", URL: srv1.Listener.Addr().String()}: {},
		{Name: "example", URL: srv2.Listener.Addr().String()}: {},
	}

	for len(expect) > 0 {
		var req Request
		select {
		case <-ctx.Done():
			t.Error("timeout waiting for requests")
			return
		case req = <-incoming:
		}

		if _, ok := expect[req]; ok {
			delete(expect, req)
		} else {
			t.Error("unexpected request", req)
			return
		}
	}
}
