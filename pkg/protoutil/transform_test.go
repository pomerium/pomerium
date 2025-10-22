package protoutil

import (
	"testing"
	"time"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestTransform(t *testing.T) {
	t.Parallel()

	t1 := time.Now()
	original := &envoy_service_auth_v3.CheckRequest{
		Attributes: &envoy_service_auth_v3.AttributeContext{
			Source: &envoy_service_auth_v3.AttributeContext_Peer{
				Address: &envoy_config_core_v3.Address{
					Address: &envoy_config_core_v3.Address_SocketAddress{
						SocketAddress: &envoy_config_core_v3.SocketAddress{
							Protocol: envoy_config_core_v3.SocketAddress_TCP,
							Address:  "SOURCE",
							PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
								PortValue: 1234,
							},
						},
					},
				},
				Service: "SERVICE",
				Labels: map[string]string{
					"LABEL_KEY": "LABEL_VALUE",
				},
				Principal:   "PRINCIPAL",
				Certificate: "CERTIFICATE",
			},
			Destination: &envoy_service_auth_v3.AttributeContext_Peer{
				Address: &envoy_config_core_v3.Address{
					Address: &envoy_config_core_v3.Address_SocketAddress{
						SocketAddress: &envoy_config_core_v3.SocketAddress{
							Protocol: envoy_config_core_v3.SocketAddress_TCP,
							Address:  "DESTINATION",
							PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
								PortValue: 5678,
							},
						},
					},
				},
				Service: "SERVICE",
				Labels: map[string]string{
					"LABEL_KEY": "LABEL_VALUE",
				},
				Principal:   "PRINCIPAL",
				Certificate: "CERTIFICATE",
			},
			Request: &envoy_service_auth_v3.AttributeContext_Request{
				Time: timestamppb.New(t1),
				Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
					Id:     "REQUEST_ID",
					Method: "METHOD",
					Headers: map[string]string{
						"HEADER_KEY": "HEADER_VALUE",
					},
					Path:     "PATH",
					Host:     "HOST",
					Scheme:   "SCHEME",
					Query:    "QUERY",
					Fragment: "FRAGMENT",
					Size:     23,
					Protocol: "PROTOCOL",
					Body:     "BODY",
					RawBody:  []byte("RAW_BODY"),
				},
			},
		},
	}
	transformed, err := Transform(original, func(_ protoreflect.FieldDescriptor, v protoreflect.Value) (protoreflect.Value, error) {
		switch vv := v.Interface().(type) {
		case []byte:
			return protoreflect.ValueOfBytes(append([]byte("TRANSFORM_"), vv...)), nil
		case string:
			return protoreflect.ValueOfString("TRANSFORM_" + vv), nil
		}
		return v, nil
	})
	require.NoError(t, err)
	if msg, ok := transformed.(*envoy_service_auth_v3.CheckRequest); assert.True(t, ok) {
		assert.Equal(t, "TRANSFORM_SOURCE",
			msg.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress())
		assert.Equal(t, "TRANSFORM_SERVICE",
			msg.GetAttributes().GetSource().GetService())
		assert.Equal(t, map[string]string{"LABEL_KEY": "TRANSFORM_LABEL_VALUE"},
			msg.GetAttributes().GetSource().GetLabels())
		assert.Equal(t, "TRANSFORM_PRINCIPAL",
			msg.GetAttributes().GetSource().GetPrincipal())
		assert.Equal(t, "TRANSFORM_CERTIFICATE",
			msg.GetAttributes().GetSource().GetCertificate())

		assert.Equal(t, "TRANSFORM_DESTINATION",
			msg.GetAttributes().GetDestination().GetAddress().GetSocketAddress().GetAddress())
		assert.Equal(t, "TRANSFORM_SERVICE",
			msg.GetAttributes().GetDestination().GetService())
		assert.Equal(t, map[string]string{"LABEL_KEY": "TRANSFORM_LABEL_VALUE"},
			msg.GetAttributes().GetDestination().GetLabels())
		assert.Equal(t, "TRANSFORM_PRINCIPAL",
			msg.GetAttributes().GetDestination().GetPrincipal())
		assert.Equal(t, "TRANSFORM_CERTIFICATE",
			msg.GetAttributes().GetDestination().GetCertificate())

		assert.Equal(t, "TRANSFORM_REQUEST_ID",
			msg.GetAttributes().GetRequest().GetHttp().GetId())
		assert.Equal(t, "TRANSFORM_METHOD",
			msg.GetAttributes().GetRequest().GetHttp().GetMethod())
		assert.Equal(t, map[string]string{"HEADER_KEY": "TRANSFORM_HEADER_VALUE"},
			msg.GetAttributes().GetRequest().GetHttp().GetHeaders())
		assert.Equal(t, "TRANSFORM_PATH",
			msg.GetAttributes().GetRequest().GetHttp().GetPath())
		assert.Equal(t, "TRANSFORM_HOST",
			msg.GetAttributes().GetRequest().GetHttp().GetHost())
		assert.Equal(t, "TRANSFORM_SCHEME",
			msg.GetAttributes().GetRequest().GetHttp().GetScheme())
		assert.Equal(t, "TRANSFORM_QUERY",
			msg.GetAttributes().GetRequest().GetHttp().GetQuery())
		assert.Equal(t, "TRANSFORM_FRAGMENT",
			msg.GetAttributes().GetRequest().GetHttp().GetFragment())
		assert.Equal(t, "TRANSFORM_PROTOCOL",
			msg.GetAttributes().GetRequest().GetHttp().GetProtocol())
		assert.Equal(t, "TRANSFORM_BODY",
			msg.GetAttributes().GetRequest().GetHttp().GetBody())
		assert.Equal(t, []byte("TRANSFORM_RAW_BODY"),
			msg.GetAttributes().GetRequest().GetHttp().GetRawBody())
	}
}
