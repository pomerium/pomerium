// package otelconfig contains OTEL config fields, separated to avoid import cycles.
package otelconfig

import (
	"fmt"
	"math"
	"reflect"
	"strconv"
	"time"

	"github.com/mitchellh/mapstructure"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	DefaultScheduleDelay      time.Duration = sdktrace.DefaultScheduleDelay * time.Millisecond
	MinimumScheduleDelay      time.Duration = 100 * time.Millisecond
	DefaultMaxExportBatchSize               = sdktrace.DefaultMaxExportBatchSize
	MinimumMaxExportBatchSize               = 1
)

type Duration time.Duration

func (d *Duration) ToProto() *durationpb.Duration {
	if d == nil {
		return nil
	}
	return durationpb.New(time.Duration(*d))
}

// OtelDurationFunc returns a DecodeHookFunc that converts durations represented
// as integer milliseconds into time.Duration values.
func OtelDurationFunc() mapstructure.DecodeHookFunc {
	durationType := reflect.TypeFor[Duration]()
	return func(_, t reflect.Type, data any) (any, error) {
		if t != durationType {
			return data, nil
		}

		num, err := strconv.ParseInt(fmt.Sprint(data), 10, 64)
		if err != nil {
			return nil, err
		}
		return max(0, min(math.MaxInt64, time.Duration(num)*time.Millisecond)), nil
	}
}

type Config struct {
	OtelTracesExporter             *string   `mapstructure:"otel_traces_exporter" yaml:"otel_traces_exporter,omitempty"`
	OtelTracesSamplerArg           *float64  `mapstructure:"otel_traces_sampler_arg" yaml:"otel_traces_sampler_arg,omitempty"`
	OtelResourceAttributes         []string  `mapstructure:"otel_resource_attributes" yaml:"otel_resource_attributes,omitempty"`
	OtelLogLevel                   *string   `mapstructure:"otel_log_level" yaml:"otel_log_level,omitempty"`
	OtelAttributeValueLengthLimit  *int32    `mapstructure:"otel_attribute_value_length_limit" yaml:"otel_attribute_value_length_limit,omitempty"`
	OtelExporterOtlpEndpoint       *string   `mapstructure:"otel_exporter_otlp_endpoint" yaml:"otel_exporter_otlp_endpoint,omitempty"`
	OtelExporterOtlpTracesEndpoint *string   `mapstructure:"otel_exporter_otlp_traces_endpoint" yaml:"otel_exporter_otlp_traces_endpoint,omitempty"`
	OtelExporterOtlpProtocol       *string   `mapstructure:"otel_exporter_otlp_protocol" yaml:"otel_exporter_otlp_protocol,omitempty"`
	OtelExporterOtlpTracesProtocol *string   `mapstructure:"otel_exporter_otlp_traces_protocol" yaml:"otel_exporter_otlp_traces_protocol,omitempty"`
	OtelExporterOtlpHeaders        []string  `mapstructure:"otel_exporter_otlp_headers" yaml:"otel_exporter_otlp_headers,omitempty"`
	OtelExporterOtlpTracesHeaders  []string  `mapstructure:"otel_exporter_otlp_traces_headers" yaml:"otel_exporter_otlp_traces_headers,omitempty"`
	OtelExporterOtlpTimeout        *Duration `mapstructure:"otel_exporter_otlp_timeout" yaml:"otel_exporter_otlp_timeout,omitempty"`
	OtelExporterOtlpTracesTimeout  *Duration `mapstructure:"otel_exporter_otlp_traces_timeout" yaml:"otel_exporter_otlp_traces_timeout,omitempty"`
	OtelBspScheduleDelay           *Duration `mapstructure:"otel_bsp_schedule_delay" yaml:"otel_bsp_schedule_delay,omitempty"`
	OtelBspMaxExportBatchSize      *int32    `mapstructure:"otel_bsp_max_export_batch_size" yaml:"otel_bsp_max_export_batch_size,omitempty"`
}
