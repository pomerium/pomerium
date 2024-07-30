// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        (unknown)
// source: github.com/pomerium/pomerium/pkg/protoutil/paths/testdata/test.proto

package testdata

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Contains field types not found anywhere in envoy
type UnusualFields struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BoolToAny   map[bool]*anypb.Any   `protobuf:"bytes,1,rep,name=bool_to_any,json=boolToAny,proto3" json:"bool_to_any,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Int32ToAny  map[int32]*anypb.Any  `protobuf:"bytes,2,rep,name=int32_to_any,json=int32ToAny,proto3" json:"int32_to_any,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Int64ToAny  map[int64]*anypb.Any  `protobuf:"bytes,3,rep,name=int64_to_any,json=int64ToAny,proto3" json:"int64_to_any,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Uint32ToAny map[uint32]*anypb.Any `protobuf:"bytes,4,rep,name=uint32_to_any,json=uint32ToAny,proto3" json:"uint32_to_any,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Uint64ToAny map[uint64]*anypb.Any `protobuf:"bytes,5,rep,name=uint64_to_any,json=uint64ToAny,proto3" json:"uint64_to_any,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	BoolToInt64 map[bool]int64        `protobuf:"bytes,6,rep,name=bool_to_int64,json=boolToInt64,proto3" json:"bool_to_int64,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
}

func (x *UnusualFields) Reset() {
	*x = UnusualFields{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UnusualFields) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UnusualFields) ProtoMessage() {}

func (x *UnusualFields) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UnusualFields.ProtoReflect.Descriptor instead.
func (*UnusualFields) Descriptor() ([]byte, []int) {
	return file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_rawDescGZIP(), []int{0}
}

func (x *UnusualFields) GetBoolToAny() map[bool]*anypb.Any {
	if x != nil {
		return x.BoolToAny
	}
	return nil
}

func (x *UnusualFields) GetInt32ToAny() map[int32]*anypb.Any {
	if x != nil {
		return x.Int32ToAny
	}
	return nil
}

func (x *UnusualFields) GetInt64ToAny() map[int64]*anypb.Any {
	if x != nil {
		return x.Int64ToAny
	}
	return nil
}

func (x *UnusualFields) GetUint32ToAny() map[uint32]*anypb.Any {
	if x != nil {
		return x.Uint32ToAny
	}
	return nil
}

func (x *UnusualFields) GetUint64ToAny() map[uint64]*anypb.Any {
	if x != nil {
		return x.Uint64ToAny
	}
	return nil
}

func (x *UnusualFields) GetBoolToInt64() map[bool]int64 {
	if x != nil {
		return x.BoolToInt64
	}
	return nil
}

var File_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto protoreflect.FileDescriptor

var file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_rawDesc = []byte{
	0x0a, 0x44, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x6f, 0x6d,
	0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x70,
	0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x75, 0x74, 0x69, 0x6c, 0x2f, 0x70, 0x61, 0x74,
	0x68, 0x73, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x74, 0x65, 0x73, 0x74,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x08, 0x74, 0x65, 0x73, 0x74, 0x64, 0x61, 0x74, 0x61,
	0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc1, 0x07, 0x0a, 0x0d,
	0x55, 0x6e, 0x75, 0x73, 0x75, 0x61, 0x6c, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x12, 0x46, 0x0a,
	0x0b, 0x62, 0x6f, 0x6f, 0x6c, 0x5f, 0x74, 0x6f, 0x5f, 0x61, 0x6e, 0x79, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x26, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x55, 0x6e,
	0x75, 0x73, 0x75, 0x61, 0x6c, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x2e, 0x42, 0x6f, 0x6f, 0x6c,
	0x54, 0x6f, 0x41, 0x6e, 0x79, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x09, 0x62, 0x6f, 0x6f, 0x6c,
	0x54, 0x6f, 0x41, 0x6e, 0x79, 0x12, 0x49, 0x0a, 0x0c, 0x69, 0x6e, 0x74, 0x33, 0x32, 0x5f, 0x74,
	0x6f, 0x5f, 0x61, 0x6e, 0x79, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x74, 0x65,
	0x73, 0x74, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x55, 0x6e, 0x75, 0x73, 0x75, 0x61, 0x6c, 0x46, 0x69,
	0x65, 0x6c, 0x64, 0x73, 0x2e, 0x49, 0x6e, 0x74, 0x33, 0x32, 0x54, 0x6f, 0x41, 0x6e, 0x79, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x52, 0x0a, 0x69, 0x6e, 0x74, 0x33, 0x32, 0x54, 0x6f, 0x41, 0x6e, 0x79,
	0x12, 0x49, 0x0a, 0x0c, 0x69, 0x6e, 0x74, 0x36, 0x34, 0x5f, 0x74, 0x6f, 0x5f, 0x61, 0x6e, 0x79,
	0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x64, 0x61, 0x74,
	0x61, 0x2e, 0x55, 0x6e, 0x75, 0x73, 0x75, 0x61, 0x6c, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x2e,
	0x49, 0x6e, 0x74, 0x36, 0x34, 0x54, 0x6f, 0x41, 0x6e, 0x79, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52,
	0x0a, 0x69, 0x6e, 0x74, 0x36, 0x34, 0x54, 0x6f, 0x41, 0x6e, 0x79, 0x12, 0x4c, 0x0a, 0x0d, 0x75,
	0x69, 0x6e, 0x74, 0x33, 0x32, 0x5f, 0x74, 0x6f, 0x5f, 0x61, 0x6e, 0x79, 0x18, 0x04, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x28, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x55, 0x6e,
	0x75, 0x73, 0x75, 0x61, 0x6c, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x2e, 0x55, 0x69, 0x6e, 0x74,
	0x33, 0x32, 0x54, 0x6f, 0x41, 0x6e, 0x79, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b, 0x75, 0x69,
	0x6e, 0x74, 0x33, 0x32, 0x54, 0x6f, 0x41, 0x6e, 0x79, 0x12, 0x4c, 0x0a, 0x0d, 0x75, 0x69, 0x6e,
	0x74, 0x36, 0x34, 0x5f, 0x74, 0x6f, 0x5f, 0x61, 0x6e, 0x79, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x28, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x55, 0x6e, 0x75, 0x73,
	0x75, 0x61, 0x6c, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x2e, 0x55, 0x69, 0x6e, 0x74, 0x36, 0x34,
	0x54, 0x6f, 0x41, 0x6e, 0x79, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b, 0x75, 0x69, 0x6e, 0x74,
	0x36, 0x34, 0x54, 0x6f, 0x41, 0x6e, 0x79, 0x12, 0x4c, 0x0a, 0x0d, 0x62, 0x6f, 0x6f, 0x6c, 0x5f,
	0x74, 0x6f, 0x5f, 0x69, 0x6e, 0x74, 0x36, 0x34, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x28,
	0x2e, 0x74, 0x65, 0x73, 0x74, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x55, 0x6e, 0x75, 0x73, 0x75, 0x61,
	0x6c, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x2e, 0x42, 0x6f, 0x6f, 0x6c, 0x54, 0x6f, 0x49, 0x6e,
	0x74, 0x36, 0x34, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b, 0x62, 0x6f, 0x6f, 0x6c, 0x54, 0x6f,
	0x49, 0x6e, 0x74, 0x36, 0x34, 0x1a, 0x52, 0x0a, 0x0e, 0x42, 0x6f, 0x6f, 0x6c, 0x54, 0x6f, 0x41,
	0x6e, 0x79, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x53, 0x0a, 0x0f, 0x49, 0x6e, 0x74,
	0x33, 0x32, 0x54, 0x6f, 0x41, 0x6e, 0x79, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03,
	0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2a,
	0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x41, 0x6e, 0x79, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x53,
	0x0a, 0x0f, 0x49, 0x6e, 0x74, 0x36, 0x34, 0x54, 0x6f, 0x41, 0x6e, 0x79, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x03,
	0x6b, 0x65, 0x79, 0x12, 0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a,
	0x02, 0x38, 0x01, 0x1a, 0x54, 0x0a, 0x10, 0x55, 0x69, 0x6e, 0x74, 0x33, 0x32, 0x54, 0x6f, 0x41,
	0x6e, 0x79, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x54, 0x0a, 0x10, 0x55, 0x69, 0x6e,
	0x74, 0x36, 0x34, 0x54, 0x6f, 0x41, 0x6e, 0x79, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a,
	0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12,
	0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x41, 0x6e, 0x79, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a,
	0x3e, 0x0a, 0x10, 0x42, 0x6f, 0x6f, 0x6c, 0x54, 0x6f, 0x49, 0x6e, 0x74, 0x36, 0x34, 0x45, 0x6e,
	0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42,
	0x3b, 0x5a, 0x39, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x6f,
	0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f,
	0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x75, 0x74, 0x69, 0x6c, 0x2f, 0x70, 0x61,
	0x74, 0x68, 0x73, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x64, 0x61, 0x74, 0x61, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_rawDescOnce sync.Once
	file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_rawDescData = file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_rawDesc
)

func file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_rawDescGZIP() []byte {
	file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_rawDescOnce.Do(func() {
		file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_rawDescData = protoimpl.X.CompressGZIP(file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_rawDescData)
	})
	return file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_rawDescData
}

var file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_goTypes = []any{
	(*UnusualFields)(nil), // 0: testdata.UnusualFields
	nil,                   // 1: testdata.UnusualFields.BoolToAnyEntry
	nil,                   // 2: testdata.UnusualFields.Int32ToAnyEntry
	nil,                   // 3: testdata.UnusualFields.Int64ToAnyEntry
	nil,                   // 4: testdata.UnusualFields.Uint32ToAnyEntry
	nil,                   // 5: testdata.UnusualFields.Uint64ToAnyEntry
	nil,                   // 6: testdata.UnusualFields.BoolToInt64Entry
	(*anypb.Any)(nil),     // 7: google.protobuf.Any
}
var file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_depIdxs = []int32{
	1,  // 0: testdata.UnusualFields.bool_to_any:type_name -> testdata.UnusualFields.BoolToAnyEntry
	2,  // 1: testdata.UnusualFields.int32_to_any:type_name -> testdata.UnusualFields.Int32ToAnyEntry
	3,  // 2: testdata.UnusualFields.int64_to_any:type_name -> testdata.UnusualFields.Int64ToAnyEntry
	4,  // 3: testdata.UnusualFields.uint32_to_any:type_name -> testdata.UnusualFields.Uint32ToAnyEntry
	5,  // 4: testdata.UnusualFields.uint64_to_any:type_name -> testdata.UnusualFields.Uint64ToAnyEntry
	6,  // 5: testdata.UnusualFields.bool_to_int64:type_name -> testdata.UnusualFields.BoolToInt64Entry
	7,  // 6: testdata.UnusualFields.BoolToAnyEntry.value:type_name -> google.protobuf.Any
	7,  // 7: testdata.UnusualFields.Int32ToAnyEntry.value:type_name -> google.protobuf.Any
	7,  // 8: testdata.UnusualFields.Int64ToAnyEntry.value:type_name -> google.protobuf.Any
	7,  // 9: testdata.UnusualFields.Uint32ToAnyEntry.value:type_name -> google.protobuf.Any
	7,  // 10: testdata.UnusualFields.Uint64ToAnyEntry.value:type_name -> google.protobuf.Any
	11, // [11:11] is the sub-list for method output_type
	11, // [11:11] is the sub-list for method input_type
	11, // [11:11] is the sub-list for extension type_name
	11, // [11:11] is the sub-list for extension extendee
	0,  // [0:11] is the sub-list for field type_name
}

func init() { file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_init() }
func file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_init() {
	if File_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*UnusualFields); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_goTypes,
		DependencyIndexes: file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_depIdxs,
		MessageInfos:      file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_msgTypes,
	}.Build()
	File_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto = out.File
	file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_rawDesc = nil
	file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_goTypes = nil
	file_github_com_pomerium_pomerium_pkg_protoutil_paths_testdata_test_proto_depIdxs = nil
}
