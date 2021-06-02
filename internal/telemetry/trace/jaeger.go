package trace

import (
	"contrib.go.opencensus.io/exporter/jaeger"
	octrace "go.opencensus.io/trace"
)

type jaegerProvider struct {
	exporter *jaeger.Exporter
}

func (provider *jaegerProvider) Register(opts *TracingOptions) error {
	jOpts := jaeger.Options{
		ServiceName:   opts.Service,
		AgentEndpoint: opts.JaegerAgentEndpoint,
	}
	if opts.JaegerCollectorEndpoint != nil {
		jOpts.CollectorEndpoint = opts.JaegerCollectorEndpoint.String()
	}
	jex, err := jaeger.NewExporter(jOpts)
	if err != nil {
		return err
	}
	octrace.RegisterExporter(jex)
	provider.exporter = jex
	return nil
}

func (provider *jaegerProvider) Unregister() error {
	if provider.exporter == nil {
		return nil
	}
	octrace.UnregisterExporter(provider.exporter)
	provider.exporter.Flush()
	provider.exporter = nil
	return nil
}
