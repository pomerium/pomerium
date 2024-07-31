package controlplane

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	envoy_data_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	envoy_service_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protopath"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/protoutil/paths"
)

func (srv *Server) registerAccessLogHandlers() {
	envoy_service_accesslog_v3.RegisterAccessLogServiceServer(srv.GRPCServer, srv)
}

// StreamAccessLogs receives logs from envoy and prints them to stdout.
func (srv *Server) StreamAccessLogs(stream envoy_service_accesslog_v3.AccessLogService_StreamAccessLogsServer) error {
	var logName string
	for {
		msg, err := stream.Recv()
		if err != nil {
			log.Error(stream.Context()).Err(err).Msg("access log stream error, disconnecting")
			return err
		}

		if msg.Identifier != nil {
			logName = msg.Identifier.LogName
		}

		if logName == "ingress-http-listener" {
			accessLogListener(stream.Context(), msg)
		} else {
			srv.accessLogHTTP(stream.Context(), msg)
		}
	}
}

func accessLogListener(
	ctx context.Context, msg *envoy_service_accesslog_v3.StreamAccessLogsMessage,
) {
	for _, entry := range msg.GetTcpLogs().GetLogEntry() {
		failure := entry.GetCommonProperties().GetDownstreamTransportFailureReason()
		if failure == "" {
			continue
		}
		e := log.Info(ctx).Str("service", "envoy")
		dict := zerolog.Dict()
		populateCertEventDict(entry.GetCommonProperties().GetTlsProperties().GetPeerCertificateProperties(), dict)
		e.Dict("client-certificate", dict)
		e.Str("ip", entry.GetCommonProperties().GetDownstreamRemoteAddress().GetSocketAddress().GetAddress())
		e.Str("tls-sni-hostname", entry.GetCommonProperties().GetTlsProperties().GetTlsSniHostname())
		e.Str("downstream-transport-failure-reason", failure)
		e.Msg("listener connection failure")
	}
}

func (srv *Server) accessLogHTTP(
	ctx context.Context, msg *envoy_service_accesslog_v3.StreamAccessLogsMessage,
) {
	for _, entry := range msg.GetHttpLogs().LogEntry {
		reqPath := entry.GetRequest().GetPath()
		var evt *zerolog.Event
		if reqPath == "/ping" || reqPath == "/healthz" {
			evt = log.Debug(ctx)
		} else {
			evt = log.Info(ctx)
		}
		evt = evt.Str("service", "envoy")

		fields := srv.currentConfig.Load().Options.GetAccessLogFields()
		for _, field := range fields {
			evt = populateLogEvent(field, evt, entry)
		}
		// headers are selected in the envoy access logs config, so we can log all of them here
		if len(entry.GetRequest().GetRequestHeaders()) > 0 {
			evt = evt.Interface("headers", entry.GetRequest().GetRequestHeaders())
		}
		evt.Msg("http-request")
	}
}

type accessLogEntry interface {
	proto.Message
	*envoy_data_accesslog_v3.HTTPAccessLogEntry | *envoy_data_accesslog_v3.TCPAccessLogEntry
}

func populateLogEvent[T accessLogEntry](
	field log.AccessLogField,
	evt *zerolog.Event,
	entry T,
) *zerolog.Event {
	if !field.IsWellKnownField() && field.IsDynamicField() {
		name, pathStr, _ := strings.Cut(string(field), "=")
		name = strings.ToValidUTF8(strings.TrimSpace(name), "")
		path, err := paths.ParseFrom(entry.ProtoReflect().Descriptor(), pathStr)
		if err != nil {
			if errors.Is(err, paths.ErrFieldNotFound) {
				return evt
			}
			return evt.Str(name, fmt.Sprintf("<error: %s>", err.Error()))
		}
		return populateLogEventByPath(name, path, evt, entry)
	}

	switch entry := proto.Message(entry).(type) {
	case *envoy_data_accesslog_v3.HTTPAccessLogEntry:
		referer, _, _ := strings.Cut(entry.GetRequest().GetReferer(), "?")
		path, query, _ := strings.Cut(entry.GetRequest().GetPath(), "?")

		switch field {
		case log.AccessLogFieldAuthority:
			return evt.Str(string(field), entry.GetRequest().GetAuthority())
		case log.AccessLogFieldDuration:
			dur := entry.GetCommonProperties().GetTimeToLastDownstreamTxByte().AsDuration()
			return evt.Dur(string(field), dur)
		case log.AccessLogFieldForwardedFor:
			return evt.Str(string(field), entry.GetRequest().GetForwardedFor())
		case log.AccessLogFieldIP:
			return evt.Str(string(field), entry.GetCommonProperties().GetDownstreamRemoteAddress().GetSocketAddress().GetAddress())
		case log.AccessLogFieldMethod:
			return evt.Str(string(field), entry.GetRequest().GetRequestMethod().String())
		case log.AccessLogFieldPath:
			return evt.Str(string(field), path)
		case log.AccessLogFieldQuery:
			return evt.Str(string(field), query)
		case log.AccessLogFieldReferer:
			return evt.Str(string(field), referer)
		case log.AccessLogFieldRequestID:
			return evt.Str(string(field), entry.GetRequest().GetRequestId())
		case log.AccessLogFieldResponseCode:
			return evt.Uint32(string(field), entry.GetResponse().GetResponseCode().GetValue())
		case log.AccessLogFieldResponseCodeDetails:
			return evt.Str(string(field), entry.GetResponse().GetResponseCodeDetails())
		case log.AccessLogFieldSize:
			return evt.Uint64(string(field), entry.GetResponse().GetResponseBodyBytes())
		case log.AccessLogFieldUpstreamCluster:
			return evt.Str(string(field), entry.GetCommonProperties().GetUpstreamCluster())
		case log.AccessLogFieldUserAgent:
			return evt.Str(string(field), entry.GetRequest().GetUserAgent())
		case log.AccessLogFieldClientCertificate:
			dict := zerolog.Dict()
			populateCertEventDict(entry.GetCommonProperties().GetTlsProperties().GetPeerCertificateProperties(), dict)
			return evt.Dict(string(field), dict)
		}
	}

	return evt
}

func populateCertEventDict(cert *envoy_data_accesslog_v3.TLSProperties_CertificateProperties, dict *zerolog.Event) {
	if cert.Issuer != "" {
		dict.Str("issuer", cert.Issuer)
	}
	if cert.Subject != "" {
		dict.Str("subject", cert.Subject)
	}
	if len(cert.SubjectAltName) > 0 {
		arr := zerolog.Arr()
		for _, san := range cert.SubjectAltName {
			// follow openssl GENERAL_NAME_print formatting
			// envoy only provides dns and uri SANs at the moment
			switch san := san.GetSan().(type) {
			case *envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName_Dns:
				arr.Str("DNS:" + san.Dns)
			case *envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName_Uri:
				arr.Str("URI:" + san.Uri)
			}
		}
		dict.Array("subjectAltName", arr)
	}
}

func populateLogEventByPath(
	name string,
	path protopath.Path,
	evt *zerolog.Event,
	entry proto.Message,
) *zerolog.Event {
	// omit the root step in the path; if one is provided to paths.Dereference,
	// it *must* match the root message descriptor.
	value, err := paths.Evaluate(entry, path[1:])
	if err != nil {
		return evt.Str(name, fmt.Sprintf("<error: %s>", err.Error()))
	}
	if !value.IsValid() {
		return evt
	}
	switch value := value.Interface().(type) {
	case protoreflect.Message:
		jsonData, err := protojson.Marshal(value.Interface())
		if err != nil {
			return evt.Str(name, fmt.Sprintf("<error: %s>", err.Error()))
		}
		return evt.RawJSON(name, jsonData)
	case protoreflect.List:
		list := zerolog.Arr()
		for i := 0; i < value.Len(); i++ {
			switch element := value.Get(i).Interface().(type) {
			case protoreflect.Message:
				jsonData, err := protojson.Marshal(element.Interface())
				if err != nil {
					list = list.Str(fmt.Sprintf("<error: %s>", err.Error()))
					continue
				}
				list = list.RawJSON(jsonData)
			default:
				list = list.Interface(element)
			}
		}
		return evt.Array(name, list)
	case protoreflect.Map:
		dict := zerolog.Dict()
		type pair struct {
			k string
			v protoreflect.Value
		}
		pairs := make([]pair, 0, value.Len())
		value.Range(func(key protoreflect.MapKey, value protoreflect.Value) bool {
			pairs = append(pairs, pair{key.String(), value})
			return true
		})
		slices.SortFunc(pairs, func(i, j pair) int {
			return cmp.Compare(i.k, j.k)
		})
		for _, kv := range pairs {
			switch value := kv.v.Interface().(type) {
			case protoreflect.Message:
				jsonData, err := protojson.Marshal(value.Interface())
				if err != nil {
					dict = dict.Str(kv.k, fmt.Sprintf("<error: %s>", err.Error()))
					continue
				}
				dict = dict.RawJSON(kv.k, jsonData)
			default:
				dict = dict.Interface(kv.k, value)
			}
		}
		return evt.Dict(name, dict)
	case protoreflect.EnumNumber:
		var fd protoreflect.FieldDescriptor
		last := path.Index(-1)
		switch last.Kind() {
		case protopath.FieldAccessStep:
			fd = last.FieldDescriptor()
		case protopath.MapIndexStep, protopath.ListIndexStep:
			fd = path.Index(-2).FieldDescriptor()
		}
		return evt.Str(name, string(fd.Enum().Values().ByNumber(value).Name()))
	default:
		return evt.Any(name, value)
	}
}
