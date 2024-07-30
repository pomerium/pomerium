package controlplane

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_data_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	envoy_service_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protopath"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func (srv *Server) registerAccessLogHandlers() {
	envoy_service_accesslog_v3.RegisterAccessLogServiceServer(srv.GRPCServer, srv)
}

// StreamAccessLogs receives logs from envoy and prints them to stdout.
func (srv *Server) StreamAccessLogs(stream envoy_service_accesslog_v3.AccessLogService_StreamAccessLogsServer) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			log.Error(stream.Context()).Err(err).Msg("access log stream error, disconnecting")
			return err
		}

		srv.handleAccessLog(stream.Context(), msg)
	}
}

func (srv *Server) handleAccessLog(
	ctx context.Context,
	msg *envoy_service_accesslog_v3.StreamAccessLogsMessage,
) {
	for _, entry := range msg.GetHttpLogs().GetLogEntry() {
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

func populateLogEvent(
	field log.AccessLogField,
	evt *zerolog.Event,
	entry *envoy_data_accesslog_v3.HTTPAccessLogEntry,
) *zerolog.Event {
	referer, _, _ := strings.Cut(entry.GetRequest().GetReferer(), "?")
	path, query, _ := strings.Cut(entry.GetRequest().GetPath(), "?")

	if !field.IsWellKnownField() {
		name, pathStr, ok := strings.Cut(string(field), "=")
		if !ok {
			return evt
		}
		name = strings.ToValidUTF8(strings.TrimSpace(name), "")
		path, err := protoutil.ParsePath(entry.ProtoReflect(), pathStr)
		if err != nil {
			return evt.Str(name, fmt.Sprintf("<error: %s>", err.Error()))
		}
		return populateLogEventByPath(name, path, evt, entry)
	}

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
	case log.AccessLogFieldDestIP:
		return evt.Str(string(field), entry.GetCommonProperties().GetDownstreamLocalAddress().GetSocketAddress().GetAddress())
	case log.AccessLogFieldDestPort:
		switch value := entry.GetCommonProperties().GetDownstreamLocalAddress().GetSocketAddress().GetPortSpecifier().(type) {
		case *envoy_config_core_v3.SocketAddress_NamedPort:
			return evt.Str(string(field), value.NamedPort)
		case *envoy_config_core_v3.SocketAddress_PortValue:
			return evt.Uint32(string(field), value.PortValue)
		}
	case log.AccessLogFieldProtocolVersion:
		return evt.Str(string(field), entry.GetProtocolVersion().String())
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
	case log.AccessLogFieldUpstreamTransportFailureReason:
		if reason := entry.GetCommonProperties().GetUpstreamTransportFailureReason(); reason != "" {
			return evt.Str(string(field), reason)
		}
	case log.AccessLogFieldDownstreamTransportFailureReason:
		if reason := entry.GetCommonProperties().GetDownstreamTransportFailureReason(); reason != "" {
			return evt.Str(string(field), reason)
		}
	case log.AccessLogFieldTLSVersion:
		if version := entry.GetCommonProperties().GetTlsProperties().GetTlsVersion(); version != 0 {
			return evt.Str(string(field), version.String())
		}
	case log.AccessLogFieldTLSSNIHostname:
		if hostname := entry.GetCommonProperties().GetTlsProperties().GetTlsSniHostname(); hostname != "" {
			return evt.Str(string(field), hostname)
		}
	case log.AccessLogFieldTLSCipherSuite:
		if id := entry.GetCommonProperties().GetTlsProperties().GetTlsCipherSuite().GetValue(); id != 0 {
			name := tls.CipherSuiteName(uint16(id))
			return evt.Str(string(field), name)
		}
	case log.AccessLogFieldTLSLocalCert:
		if cert := entry.GetCommonProperties().GetTlsProperties().GetLocalCertificateProperties(); cert != nil {
			dict := zerolog.Dict()
			populateCertEventDict(cert, dict)
			return evt.Dict(string(field), dict)
		}
	case log.AccessLogFieldTLSPeerCert:
		if cert := entry.GetCommonProperties().GetTlsProperties().GetPeerCertificateProperties(); cert != nil {
			dict := zerolog.Dict()
			populateCertEventDict(cert, dict)
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
	entry *envoy_data_accesslog_v3.HTTPAccessLogEntry,
) *zerolog.Event {
	value, err := protoutil.DereferencePath(entry, path)
	if err != nil {
		return evt.Str(name, fmt.Sprintf("<error: %s>", err.Error()))
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
			list = list.Interface(value.Get(i).Interface())
		}
		return evt.Array(name, list)
	case protoreflect.Map:
		dict := zerolog.Dict()
		value.Range(func(key protoreflect.MapKey, value protoreflect.Value) bool {
			switch value := value.Interface().(type) {
			case protoreflect.Message:
				jsonData, err := protojson.Marshal(value.Interface())
				if err != nil {
					dict = dict.Str(key.String(), fmt.Sprintf("<error: %s>", err.Error()))
					return true
				}
				dict = dict.RawJSON(key.String(), jsonData)
			default:
				dict = dict.Interface(key.String(), value)
			}
			return true
		})
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
