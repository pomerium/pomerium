package telemetry

import "testing"

func TestRegisterTracing(t *testing.T) {
	tests := []struct {
		name    string
		opts    *TracingOptions
		wantErr bool
	}{
		{"jaeger", &TracingOptions{JaegerAgentEndpoint: "localhost:6831", Service: "all", Provider: "jaeger"}, false},
		{"jaeger with debug", &TracingOptions{JaegerAgentEndpoint: "localhost:6831", Service: "all", Provider: "jaeger", Debug: true}, false},
		{"jaeger no endpoint", &TracingOptions{JaegerAgentEndpoint: "", Service: "all", Provider: "jaeger"}, true},
		{"unknown provider", &TracingOptions{JaegerAgentEndpoint: "localhost:0", Service: "all", Provider: "Lucius Cornelius Sulla"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := RegisterTracing(tt.opts); (err != nil) != tt.wantErr {
				t.Errorf("RegisterTracing() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
