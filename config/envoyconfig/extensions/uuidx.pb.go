// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.2
// 	protoc        (unknown)
// source: github.com/pomerium/pomerium/config/envoyconfig/extensions/uuidx.proto

package extensions

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type UuidxRequestIdConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PackTraceReason              *wrapperspb.BoolValue `protobuf:"bytes,1,opt,name=pack_trace_reason,json=packTraceReason,proto3" json:"pack_trace_reason,omitempty"`
	UseRequestIdForTraceSampling *wrapperspb.BoolValue `protobuf:"bytes,2,opt,name=use_request_id_for_trace_sampling,json=useRequestIdForTraceSampling,proto3" json:"use_request_id_for_trace_sampling,omitempty"`
}

func (x *UuidxRequestIdConfig) Reset() {
	*x = UuidxRequestIdConfig{}
	mi := &file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UuidxRequestIdConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UuidxRequestIdConfig) ProtoMessage() {}

func (x *UuidxRequestIdConfig) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UuidxRequestIdConfig.ProtoReflect.Descriptor instead.
func (*UuidxRequestIdConfig) Descriptor() ([]byte, []int) {
	return file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_rawDescGZIP(), []int{0}
}

func (x *UuidxRequestIdConfig) GetPackTraceReason() *wrapperspb.BoolValue {
	if x != nil {
		return x.PackTraceReason
	}
	return nil
}

func (x *UuidxRequestIdConfig) GetUseRequestIdForTraceSampling() *wrapperspb.BoolValue {
	if x != nil {
		return x.UseRequestIdForTraceSampling
	}
	return nil
}

var File_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto protoreflect.FileDescriptor

var file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_rawDesc = []byte{
	0x0a, 0x46, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x6f, 0x6d,
	0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x75, 0x75, 0x69,
	0x64, 0x78, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x13, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69,
	0x75, 0x6d, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x1a, 0x1e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77,
	0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc3, 0x01,
	0x0a, 0x14, 0x55, 0x75, 0x69, 0x64, 0x78, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x46, 0x0a, 0x11, 0x70, 0x61, 0x63, 0x6b, 0x5f, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x5f, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x42, 0x6f, 0x6f, 0x6c, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x0f, 0x70,
	0x61, 0x63, 0x6b, 0x54, 0x72, 0x61, 0x63, 0x65, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12, 0x63,
	0x0a, 0x21, 0x75, 0x73, 0x65, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64,
	0x5f, 0x66, 0x6f, 0x72, 0x5f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x5f, 0x73, 0x61, 0x6d, 0x70, 0x6c,
	0x69, 0x6e, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x42, 0x6f, 0x6f, 0x6c,
	0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x1c, 0x75, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x49, 0x64, 0x46, 0x6f, 0x72, 0x54, 0x72, 0x61, 0x63, 0x65, 0x53, 0x61, 0x6d, 0x70, 0x6c,
	0x69, 0x6e, 0x67, 0x42, 0x3c, 0x5a, 0x3a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72,
	0x69, 0x75, 0x6d, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_rawDescOnce sync.Once
	file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_rawDescData = file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_rawDesc
)

func file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_rawDescGZIP() []byte {
	file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_rawDescOnce.Do(func() {
		file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_rawDescData = protoimpl.X.CompressGZIP(file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_rawDescData)
	})
	return file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_rawDescData
}

var file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_goTypes = []any{
	(*UuidxRequestIdConfig)(nil), // 0: pomerium.extensions.UuidxRequestIdConfig
	(*wrapperspb.BoolValue)(nil), // 1: google.protobuf.BoolValue
}
var file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_depIdxs = []int32{
	1, // 0: pomerium.extensions.UuidxRequestIdConfig.pack_trace_reason:type_name -> google.protobuf.BoolValue
	1, // 1: pomerium.extensions.UuidxRequestIdConfig.use_request_id_for_trace_sampling:type_name -> google.protobuf.BoolValue
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_init() }
func file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_init() {
	if File_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_goTypes,
		DependencyIndexes: file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_depIdxs,
		MessageInfos:      file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_msgTypes,
	}.Build()
	File_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto = out.File
	file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_rawDesc = nil
	file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_goTypes = nil
	file_github_com_pomerium_pomerium_config_envoyconfig_extensions_uuidx_proto_depIdxs = nil
}
