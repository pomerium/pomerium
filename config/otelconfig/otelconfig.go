// package otelconfig contains OTEL config fields, separated to avoid import cycles.
package otelconfig

type Config struct {
	OtelTracesExporter             *string  `mapstructure:"otel_traces_exporter" yaml:"otel_traces_exporter,omitempty"`
	OtelTracesSamplerArg           *float64 `mapstructure:"otel_traces_sampler_arg" yaml:"otel_traces_sampler_arg,omitempty"`
	OtelResourceAttributes         []string `mapstructure:"otel_resource_attributes" yaml:"otel_resource_attributes,omitempty"`
	OtelLogLevel                   *string  `mapstructure:"otel_log_level" yaml:"otel_log_level,omitempty"`
	OtelAttributeValueLengthLimit  *int32   `mapstructure:"otel_attribute_value_length_limit" yaml:"otel_attribute_value_length_limit,omitempty"`
	OtelExporterOtlpEndpoint       *string  `mapstructure:"otel_exporter_otlp_endpoint" yaml:"otel_exporter_otlp_endpoint,omitempty"`
	OtelExporterOtlpTracesEndpoint *string  `mapstructure:"otel_exporter_otlp_traces_endpoint" yaml:"otel_exporter_otlp_traces_endpoint,omitempty"`
	OtelExporterOtlpProtocol       *string  `mapstructure:"otel_exporter_otlp_protocol" yaml:"otel_exporter_otlp_protocol,omitempty"`
	OtelExporterOtlpTracesProtocol *string  `mapstructure:"otel_exporter_otlp_traces_protocol" yaml:"otel_exporter_otlp_traces_protocol,omitempty"`
	OtelExporterOtlpHeaders        []string `mapstructure:"otel_exporter_otlp_headers" yaml:"otel_exporter_otlp_headers,omitempty"`
	OtelExporterOtlpTracesHeaders  []string `mapstructure:"otel_exporter_otlp_traces_headers" yaml:"otel_exporter_otlp_traces_headers,omitempty"`
	OtelExporterOtlpTimeout        *int64   `mapstructure:"otel_exporter_otlp_timeout" yaml:"otel_exporter_otlp_timeout,omitempty"`
	OtelExporterOtlpTracesTimeout  *int64   `mapstructure:"otel_exporter_otlp_traces_timeout" yaml:"otel_exporter_otlp_traces_timeout,omitempty"`
	OtelBspScheduleDelay           *int32   `mapstructure:"otel_bsp_schedule_delay" yaml:"otel_bsp_schedule_delay,omitempty"`
	OtelBspMaxExportBatchSize      *int32   `mapstructure:"otel_bsp_max_export_batch_size" yaml:"otel_bsp_max_export_batch_size,omitempty"`
}
