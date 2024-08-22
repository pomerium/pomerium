// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        (unknown)
// source: connect.proto

package connect

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// SubscribeRequest is used to subscribe to a stream of messages
// from the Zero Cloud to the Pomerium Core.
//
// The Authorization: Bearer header must contain a valid token,
// that belongs to a cluster identity with appropriate claims set.
type SubscribeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hostname string `protobuf:"bytes,1,opt,name=hostname,proto3" json:"hostname,omitempty"`
	Version  string `protobuf:"bytes,2,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *SubscribeRequest) Reset() {
	*x = SubscribeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_connect_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubscribeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubscribeRequest) ProtoMessage() {}

func (x *SubscribeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_connect_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubscribeRequest.ProtoReflect.Descriptor instead.
func (*SubscribeRequest) Descriptor() ([]byte, []int) {
	return file_connect_proto_rawDescGZIP(), []int{0}
}

func (x *SubscribeRequest) GetHostname() string {
	if x != nil {
		return x.Hostname
	}
	return ""
}

func (x *SubscribeRequest) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

// Message is an aggregate of all possible messages that can be sent
// from the cloud to the core in managed mode.
type Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Message:
	//
	//	*Message_ConfigUpdated
	//	*Message_BootstrapConfigUpdated
	//	*Message_TelemetryRequest
	Message isMessage_Message `protobuf_oneof:"message"`
}

func (x *Message) Reset() {
	*x = Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_connect_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_connect_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_connect_proto_rawDescGZIP(), []int{1}
}

func (m *Message) GetMessage() isMessage_Message {
	if m != nil {
		return m.Message
	}
	return nil
}

func (x *Message) GetConfigUpdated() *ConfigUpdated {
	if x, ok := x.GetMessage().(*Message_ConfigUpdated); ok {
		return x.ConfigUpdated
	}
	return nil
}

func (x *Message) GetBootstrapConfigUpdated() *BootstrapConfigUpdated {
	if x, ok := x.GetMessage().(*Message_BootstrapConfigUpdated); ok {
		return x.BootstrapConfigUpdated
	}
	return nil
}

func (x *Message) GetTelemetryRequest() *TelemetryRequest {
	if x, ok := x.GetMessage().(*Message_TelemetryRequest); ok {
		return x.TelemetryRequest
	}
	return nil
}

type isMessage_Message interface {
	isMessage_Message()
}

type Message_ConfigUpdated struct {
	ConfigUpdated *ConfigUpdated `protobuf:"bytes,1,opt,name=config_updated,json=configUpdated,proto3,oneof"`
}

type Message_BootstrapConfigUpdated struct {
	BootstrapConfigUpdated *BootstrapConfigUpdated `protobuf:"bytes,2,opt,name=bootstrap_config_updated,json=bootstrapConfigUpdated,proto3,oneof"`
}

type Message_TelemetryRequest struct {
	TelemetryRequest *TelemetryRequest `protobuf:"bytes,3,opt,name=telemetry_request,json=telemetryRequest,proto3,oneof"`
}

func (*Message_ConfigUpdated) isMessage_Message() {}

func (*Message_BootstrapConfigUpdated) isMessage_Message() {}

func (*Message_TelemetryRequest) isMessage_Message() {}

// ConfigUpdated is sent when the configuration has been updated
// for the connected Pomerium Core deployment
type ConfigUpdated struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// version of the configuration changeset
	ChangesetVersion int64 `protobuf:"varint,1,opt,name=changeset_version,json=changesetVersion,proto3" json:"changeset_version,omitempty"`
}

func (x *ConfigUpdated) Reset() {
	*x = ConfigUpdated{}
	if protoimpl.UnsafeEnabled {
		mi := &file_connect_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigUpdated) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigUpdated) ProtoMessage() {}

func (x *ConfigUpdated) ProtoReflect() protoreflect.Message {
	mi := &file_connect_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigUpdated.ProtoReflect.Descriptor instead.
func (*ConfigUpdated) Descriptor() ([]byte, []int) {
	return file_connect_proto_rawDescGZIP(), []int{2}
}

func (x *ConfigUpdated) GetChangesetVersion() int64 {
	if x != nil {
		return x.ChangesetVersion
	}
	return 0
}

// BootstrapConfigUpdated is sent when the bootstrap configuration has been
// updated. Bootstrap configuration is received via cluster API directly, and
// does not involve long running operations to construct it, like with a regular
// config.
type BootstrapConfigUpdated struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *BootstrapConfigUpdated) Reset() {
	*x = BootstrapConfigUpdated{}
	if protoimpl.UnsafeEnabled {
		mi := &file_connect_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BootstrapConfigUpdated) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BootstrapConfigUpdated) ProtoMessage() {}

func (x *BootstrapConfigUpdated) ProtoReflect() protoreflect.Message {
	mi := &file_connect_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BootstrapConfigUpdated.ProtoReflect.Descriptor instead.
func (*BootstrapConfigUpdated) Descriptor() ([]byte, []int) {
	return file_connect_proto_rawDescGZIP(), []int{3}
}

// TelemetryRequest is sent to request current telemetry data from the Pomerium Core to be sent to the Zero Cloud.
type TelemetryRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// include_session_analytics requests current MAU/DAU data
	SessionAnalytics *SessionAnalyticsRequest `protobuf:"bytes,1,opt,name=session_analytics,json=sessionAnalytics,proto3,oneof" json:"session_analytics,omitempty"`
	// envoy_metrics requests current envoy metrics
	EnvoyMetrics *EnvoyMetricsRequest `protobuf:"bytes,2,opt,name=envoy_metrics,json=envoyMetrics,proto3,oneof" json:"envoy_metrics,omitempty"`
	// pomerium_metrics requests current pomerium metrics
	PomeriumMetrics *PomeriumMetricsRequest `protobuf:"bytes,3,opt,name=pomerium_metrics,json=pomeriumMetrics,proto3,oneof" json:"pomerium_metrics,omitempty"`
}

func (x *TelemetryRequest) Reset() {
	*x = TelemetryRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_connect_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TelemetryRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TelemetryRequest) ProtoMessage() {}

func (x *TelemetryRequest) ProtoReflect() protoreflect.Message {
	mi := &file_connect_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TelemetryRequest.ProtoReflect.Descriptor instead.
func (*TelemetryRequest) Descriptor() ([]byte, []int) {
	return file_connect_proto_rawDescGZIP(), []int{4}
}

func (x *TelemetryRequest) GetSessionAnalytics() *SessionAnalyticsRequest {
	if x != nil {
		return x.SessionAnalytics
	}
	return nil
}

func (x *TelemetryRequest) GetEnvoyMetrics() *EnvoyMetricsRequest {
	if x != nil {
		return x.EnvoyMetrics
	}
	return nil
}

func (x *TelemetryRequest) GetPomeriumMetrics() *PomeriumMetricsRequest {
	if x != nil {
		return x.PomeriumMetrics
	}
	return nil
}

// SessionAnalyticsRequest is used to request current MAU/DAU data
type SessionAnalyticsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SessionAnalyticsRequest) Reset() {
	*x = SessionAnalyticsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_connect_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SessionAnalyticsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SessionAnalyticsRequest) ProtoMessage() {}

func (x *SessionAnalyticsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_connect_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SessionAnalyticsRequest.ProtoReflect.Descriptor instead.
func (*SessionAnalyticsRequest) Descriptor() ([]byte, []int) {
	return file_connect_proto_rawDescGZIP(), []int{5}
}

// EnvoyMetricsRequest is used to request current envoy metrics
type EnvoyMetricsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// only include metrics that match the provided labels
	Metrics []string `protobuf:"bytes,1,rep,name=metrics,proto3" json:"metrics,omitempty"`
	// only include labels that match the provided labels
	Labels []string `protobuf:"bytes,2,rep,name=labels,proto3" json:"labels,omitempty"`
}

func (x *EnvoyMetricsRequest) Reset() {
	*x = EnvoyMetricsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_connect_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnvoyMetricsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnvoyMetricsRequest) ProtoMessage() {}

func (x *EnvoyMetricsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_connect_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnvoyMetricsRequest.ProtoReflect.Descriptor instead.
func (*EnvoyMetricsRequest) Descriptor() ([]byte, []int) {
	return file_connect_proto_rawDescGZIP(), []int{6}
}

func (x *EnvoyMetricsRequest) GetMetrics() []string {
	if x != nil {
		return x.Metrics
	}
	return nil
}

func (x *EnvoyMetricsRequest) GetLabels() []string {
	if x != nil {
		return x.Labels
	}
	return nil
}

// PomeriumMetricsRequest is used to request current pomerium metrics
type PomeriumMetricsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// only include metrics that match the provided labels
	Metrics []string `protobuf:"bytes,1,rep,name=metrics,proto3" json:"metrics,omitempty"`
}

func (x *PomeriumMetricsRequest) Reset() {
	*x = PomeriumMetricsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_connect_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PomeriumMetricsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PomeriumMetricsRequest) ProtoMessage() {}

func (x *PomeriumMetricsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_connect_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PomeriumMetricsRequest.ProtoReflect.Descriptor instead.
func (*PomeriumMetricsRequest) Descriptor() ([]byte, []int) {
	return file_connect_proto_rawDescGZIP(), []int{7}
}

func (x *PomeriumMetricsRequest) GetMetrics() []string {
	if x != nil {
		return x.Metrics
	}
	return nil
}

var File_connect_proto protoreflect.FileDescriptor

var file_connect_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x0d, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2e, 0x7a, 0x65, 0x72, 0x6f, 0x22, 0x48,
	0x0a, 0x10, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x18,
	0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x8e, 0x02, 0x0a, 0x07, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x12, 0x45, 0x0a, 0x0e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x75,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x70,
	0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2e, 0x7a, 0x65, 0x72, 0x6f, 0x2e, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x48, 0x00, 0x52, 0x0d, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x12, 0x61, 0x0a, 0x18, 0x62,
	0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f,
	0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x25, 0x2e,
	0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2e, 0x7a, 0x65, 0x72, 0x6f, 0x2e, 0x42, 0x6f,
	0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x55, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x64, 0x48, 0x00, 0x52, 0x16, 0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72, 0x61,
	0x70, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x12, 0x4e,
	0x0a, 0x11, 0x74, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x74, 0x72, 0x79, 0x5f, 0x72, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x70, 0x6f, 0x6d, 0x65,
	0x72, 0x69, 0x75, 0x6d, 0x2e, 0x7a, 0x65, 0x72, 0x6f, 0x2e, 0x54, 0x65, 0x6c, 0x65, 0x6d, 0x65,
	0x74, 0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x10, 0x74, 0x65,
	0x6c, 0x65, 0x6d, 0x65, 0x74, 0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x42, 0x09,
	0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0x3c, 0x0a, 0x0d, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x12, 0x2b, 0x0a, 0x11, 0x63, 0x68,
	0x61, 0x6e, 0x67, 0x65, 0x73, 0x65, 0x74, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x10, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x65, 0x74,
	0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x18, 0x0a, 0x16, 0x42, 0x6f, 0x6f, 0x74, 0x73,
	0x74, 0x72, 0x61, 0x70, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x64, 0x22, 0xce, 0x02, 0x0a, 0x10, 0x54, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x74, 0x72, 0x79, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x58, 0x0a, 0x11, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x5f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x74, 0x69, 0x63, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x26, 0x2e, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2e, 0x7a, 0x65, 0x72,
	0x6f, 0x2e, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x74, 0x69,
	0x63, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x10, 0x73, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x74, 0x69, 0x63, 0x73, 0x88, 0x01, 0x01,
	0x12, 0x4c, 0x0a, 0x0d, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x5f, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63,
	0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69,
	0x75, 0x6d, 0x2e, 0x7a, 0x65, 0x72, 0x6f, 0x2e, 0x45, 0x6e, 0x76, 0x6f, 0x79, 0x4d, 0x65, 0x74,
	0x72, 0x69, 0x63, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x01, 0x52, 0x0c, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x88, 0x01, 0x01, 0x12, 0x55,
	0x0a, 0x10, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x5f, 0x6d, 0x65, 0x74, 0x72, 0x69,
	0x63, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x25, 0x2e, 0x70, 0x6f, 0x6d, 0x65, 0x72,
	0x69, 0x75, 0x6d, 0x2e, 0x7a, 0x65, 0x72, 0x6f, 0x2e, 0x50, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75,
	0x6d, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48,
	0x02, 0x52, 0x0f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x4d, 0x65, 0x74, 0x72, 0x69,
	0x63, 0x73, 0x88, 0x01, 0x01, 0x42, 0x14, 0x0a, 0x12, 0x5f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x5f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x74, 0x69, 0x63, 0x73, 0x42, 0x10, 0x0a, 0x0e, 0x5f,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x5f, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x42, 0x13, 0x0a,
	0x11, 0x5f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x5f, 0x6d, 0x65, 0x74, 0x72, 0x69,
	0x63, 0x73, 0x22, 0x19, 0x0a, 0x17, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x41, 0x6e, 0x61,
	0x6c, 0x79, 0x74, 0x69, 0x63, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x47, 0x0a,
	0x13, 0x45, 0x6e, 0x76, 0x6f, 0x79, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x12, 0x16,
	0x0a, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06,
	0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x22, 0x32, 0x0a, 0x16, 0x50, 0x6f, 0x6d, 0x65, 0x72, 0x69,
	0x75, 0x6d, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x07, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x32, 0x51, 0x0a, 0x07, 0x43, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x12, 0x46, 0x0a, 0x09, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69,
	0x62, 0x65, 0x12, 0x1f, 0x2e, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2e, 0x7a, 0x65,
	0x72, 0x6f, 0x2e, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2e, 0x7a,
	0x65, 0x72, 0x6f, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x30, 0x01, 0x42, 0x2f, 0x5a,
	0x2d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x6f, 0x6d, 0x65,
	0x72, 0x69, 0x75, 0x6d, 0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x70, 0x6b,
	0x67, 0x2f, 0x7a, 0x65, 0x72, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_connect_proto_rawDescOnce sync.Once
	file_connect_proto_rawDescData = file_connect_proto_rawDesc
)

func file_connect_proto_rawDescGZIP() []byte {
	file_connect_proto_rawDescOnce.Do(func() {
		file_connect_proto_rawDescData = protoimpl.X.CompressGZIP(file_connect_proto_rawDescData)
	})
	return file_connect_proto_rawDescData
}

var file_connect_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_connect_proto_goTypes = []any{
	(*SubscribeRequest)(nil),        // 0: pomerium.zero.SubscribeRequest
	(*Message)(nil),                 // 1: pomerium.zero.Message
	(*ConfigUpdated)(nil),           // 2: pomerium.zero.ConfigUpdated
	(*BootstrapConfigUpdated)(nil),  // 3: pomerium.zero.BootstrapConfigUpdated
	(*TelemetryRequest)(nil),        // 4: pomerium.zero.TelemetryRequest
	(*SessionAnalyticsRequest)(nil), // 5: pomerium.zero.SessionAnalyticsRequest
	(*EnvoyMetricsRequest)(nil),     // 6: pomerium.zero.EnvoyMetricsRequest
	(*PomeriumMetricsRequest)(nil),  // 7: pomerium.zero.PomeriumMetricsRequest
}
var file_connect_proto_depIdxs = []int32{
	2, // 0: pomerium.zero.Message.config_updated:type_name -> pomerium.zero.ConfigUpdated
	3, // 1: pomerium.zero.Message.bootstrap_config_updated:type_name -> pomerium.zero.BootstrapConfigUpdated
	4, // 2: pomerium.zero.Message.telemetry_request:type_name -> pomerium.zero.TelemetryRequest
	5, // 3: pomerium.zero.TelemetryRequest.session_analytics:type_name -> pomerium.zero.SessionAnalyticsRequest
	6, // 4: pomerium.zero.TelemetryRequest.envoy_metrics:type_name -> pomerium.zero.EnvoyMetricsRequest
	7, // 5: pomerium.zero.TelemetryRequest.pomerium_metrics:type_name -> pomerium.zero.PomeriumMetricsRequest
	0, // 6: pomerium.zero.Connect.Subscribe:input_type -> pomerium.zero.SubscribeRequest
	1, // 7: pomerium.zero.Connect.Subscribe:output_type -> pomerium.zero.Message
	7, // [7:8] is the sub-list for method output_type
	6, // [6:7] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_connect_proto_init() }
func file_connect_proto_init() {
	if File_connect_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_connect_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*SubscribeRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_connect_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_connect_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*ConfigUpdated); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_connect_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*BootstrapConfigUpdated); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_connect_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*TelemetryRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_connect_proto_msgTypes[5].Exporter = func(v any, i int) any {
			switch v := v.(*SessionAnalyticsRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_connect_proto_msgTypes[6].Exporter = func(v any, i int) any {
			switch v := v.(*EnvoyMetricsRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_connect_proto_msgTypes[7].Exporter = func(v any, i int) any {
			switch v := v.(*PomeriumMetricsRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_connect_proto_msgTypes[1].OneofWrappers = []any{
		(*Message_ConfigUpdated)(nil),
		(*Message_BootstrapConfigUpdated)(nil),
		(*Message_TelemetryRequest)(nil),
	}
	file_connect_proto_msgTypes[4].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_connect_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_connect_proto_goTypes,
		DependencyIndexes: file_connect_proto_depIdxs,
		MessageInfos:      file_connect_proto_msgTypes,
	}.Build()
	File_connect_proto = out.File
	file_connect_proto_rawDesc = nil
	file_connect_proto_goTypes = nil
	file_connect_proto_depIdxs = nil
}
