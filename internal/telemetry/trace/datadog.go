package trace

import (
	datadog "github.com/DataDog/opencensus-go-exporter-datadog"
	octrace "go.opencensus.io/trace"
)

type datadogProvider struct {
	exporter *datadog.Exporter
}

func (provider *datadogProvider) Register(opts *TracingOptions) error {
	dOpts := datadog.Options{
		Service:   opts.Service,
		TraceAddr: opts.DatadogAddress,
	}
	dex, err := datadog.NewExporter(dOpts)
	if err != nil {
		return err
	}
	octrace.RegisterExporter(dex)
	provider.exporter = dex
	return nil
}

func (provider *datadogProvider) Unregister() error {
	if provider.exporter == nil {
		return nil
	}
	octrace.UnregisterExporter(provider.exporter)
	provider.exporter.Stop()
	provider.exporter = nil
	return nil
}
