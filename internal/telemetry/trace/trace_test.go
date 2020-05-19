package trace

import (
	"net/url"
	"testing"

	"github.com/pomerium/pomerium/config"
)

func TestRegisterTracing(t *testing.T) {
	tests := []struct {
		name    string
		opts    *config.TracingOptions
		wantErr bool
	}{
		{"jaeger", &config.TracingOptions{JaegerAgentEndpoint: "localhost:6831", Service: "all", Provider: "jaeger"}, false},
		{"jaeger with debug", &config.TracingOptions{JaegerAgentEndpoint: "localhost:6831", Service: "all", Provider: "jaeger", Debug: true}, false},
		{"jaeger no endpoint", &config.TracingOptions{JaegerAgentEndpoint: "", Service: "all", Provider: "jaeger"}, true},
		{"unknown provider", &config.TracingOptions{JaegerAgentEndpoint: "localhost:0", Service: "all", Provider: "Lucius Cornelius Sulla"}, true},
		{"zipkin with debug", &config.TracingOptions{ZipkinEndpoint: &url.URL{Host: "localhost"}, Service: "all", Provider: "zipkin", Debug: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := RegisterTracing(tt.opts); (err != nil) != tt.wantErr {
				t.Errorf("RegisterTracing() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
