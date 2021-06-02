package trace

import (
	"fmt"
	stdlog "log"

	oczipkin "contrib.go.opencensus.io/exporter/zipkin"
	"github.com/openzipkin/zipkin-go"
	"github.com/openzipkin/zipkin-go/reporter"
	zipkinHTTP "github.com/openzipkin/zipkin-go/reporter/http"
	octrace "go.opencensus.io/trace"

	"github.com/pomerium/pomerium/internal/log"
)

type zipkinProvider struct {
	reporter reporter.Reporter
	exporter *oczipkin.Exporter
}

func (provider *zipkinProvider) Register(opts *TracingOptions) error {
	localEndpoint, err := zipkin.NewEndpoint(opts.Service, "")
	if err != nil {
		return fmt.Errorf("telemetry/trace: could not create local endpoint: %w", err)
	}

	provider.reporter = zipkinHTTP.NewReporter(opts.ZipkinEndpoint.String(),
		zipkinHTTP.Logger(stdlog.New(log.Logger(), "", 0)))
	provider.exporter = oczipkin.NewExporter(provider.reporter, localEndpoint)
	octrace.RegisterExporter(provider.exporter)
	return nil
}

func (provider *zipkinProvider) Unregister() error {
	if provider.exporter != nil {
		octrace.UnregisterExporter(provider.exporter)
		provider.exporter = nil
	}

	var err error
	if provider.reporter != nil {
		err = provider.reporter.Close()
		provider.reporter = nil
	}
	return err
}
