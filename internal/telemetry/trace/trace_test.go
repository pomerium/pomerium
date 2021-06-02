package trace

import (
	"net/url"
	"testing"
)

func TestGetProvider(t *testing.T) {
	tests := []struct {
		name    string
		opts    *TracingOptions
		wantErr bool
	}{
		{"jaeger", &TracingOptions{JaegerAgentEndpoint: "localhost:6831", Service: "all", Provider: "jaeger"}, false},
		{"jaeger with debug", &TracingOptions{JaegerAgentEndpoint: "localhost:6831", Service: "all", Provider: "jaeger", Debug: true}, false},
		{"jaeger no endpoint", &TracingOptions{JaegerAgentEndpoint: "", Service: "all", Provider: "jaeger"}, false},
		{"unknown provider", &TracingOptions{JaegerAgentEndpoint: "localhost:0", Service: "all", Provider: "Lucius Cornelius Sulla"}, true},
		{"zipkin with debug", &TracingOptions{ZipkinEndpoint: &url.URL{Host: "localhost"}, Service: "all", Provider: "zipkin", Debug: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := GetProvider(tt.opts); (err != nil) != tt.wantErr {
				t.Errorf("RegisterTracing() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
