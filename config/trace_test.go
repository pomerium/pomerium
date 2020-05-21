package config

import (
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func Test_NewTracingOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    *Options
		want    *TracingOptions
		wantErr bool
	}{
		{
			"jaeger_good",
			&Options{TracingProvider: "jaeger", TracingJaegerAgentEndpoint: "foo", TracingJaegerCollectorEndpoint: "http://foo"},
			&TracingOptions{Provider: "jaeger", JaegerAgentEndpoint: "foo", JaegerCollectorEndpoint: &url.URL{Scheme: "http", Host: "foo"}},
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
			&Options{TracingProvider: "zipkin", ZipkinEndpoint: "https://foo/api/v1/spans"},
			&TracingOptions{Provider: "zipkin", ZipkinEndpoint: &url.URL{Scheme: "https", Host: "foo", Path: "/api/v1/spans"}},
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
