// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.3
// source: audit.proto

package audit

import (
	context "context"
	proto "github.com/golang/protobuf/proto"
	empty "github.com/golang/protobuf/ptypes/empty"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
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

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type Record struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OrganizationId     string               `protobuf:"bytes,1,opt,name=organization_id,json=organizationId,proto3" json:"organization_id,omitempty"`
	Id                 string               `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Time               *timestamp.Timestamp `protobuf:"bytes,3,opt,name=time,proto3" json:"time,omitempty"`
	AuthenticationInfo *AuthenticationInfo  `protobuf:"bytes,4,opt,name=authentication_info,json=authenticationInfo,proto3" json:"authentication_info,omitempty"`
	Source             string               `protobuf:"bytes,5,opt,name=source,proto3" json:"source,omitempty"`
	Destination        string               `protobuf:"bytes,6,opt,name=destination,proto3" json:"destination,omitempty"`
	// Types that are assignable to Request:
	//	*Record_HttpRequest
	Request isRecord_Request `protobuf_oneof:"request"`
	// Types that are assignable to Response:
	//	*Record_HttpResponse
	Response isRecord_Response `protobuf_oneof:"response"`
	Status   *Status           `protobuf:"bytes,9,opt,name=status,proto3" json:"status,omitempty"`
	Metadata map[string]string `protobuf:"bytes,10,rep,name=metadata,proto3" json:"metadata,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Record) Reset() {
	*x = Record{}
	if protoimpl.UnsafeEnabled {
		mi := &file_audit_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Record) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Record) ProtoMessage() {}

func (x *Record) ProtoReflect() protoreflect.Message {
	mi := &file_audit_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Record.ProtoReflect.Descriptor instead.
func (*Record) Descriptor() ([]byte, []int) {
	return file_audit_proto_rawDescGZIP(), []int{0}
}

func (x *Record) GetOrganizationId() string {
	if x != nil {
		return x.OrganizationId
	}
	return ""
}

func (x *Record) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Record) GetTime() *timestamp.Timestamp {
	if x != nil {
		return x.Time
	}
	return nil
}

func (x *Record) GetAuthenticationInfo() *AuthenticationInfo {
	if x != nil {
		return x.AuthenticationInfo
	}
	return nil
}

func (x *Record) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

func (x *Record) GetDestination() string {
	if x != nil {
		return x.Destination
	}
	return ""
}

func (m *Record) GetRequest() isRecord_Request {
	if m != nil {
		return m.Request
	}
	return nil
}

func (x *Record) GetHttpRequest() *HTTPRequest {
	if x, ok := x.GetRequest().(*Record_HttpRequest); ok {
		return x.HttpRequest
	}
	return nil
}

func (m *Record) GetResponse() isRecord_Response {
	if m != nil {
		return m.Response
	}
	return nil
}

func (x *Record) GetHttpResponse() *HTTPResponse {
	if x, ok := x.GetResponse().(*Record_HttpResponse); ok {
		return x.HttpResponse
	}
	return nil
}

func (x *Record) GetStatus() *Status {
	if x != nil {
		return x.Status
	}
	return nil
}

func (x *Record) GetMetadata() map[string]string {
	if x != nil {
		return x.Metadata
	}
	return nil
}

type isRecord_Request interface {
	isRecord_Request()
}

type Record_HttpRequest struct {
	HttpRequest *HTTPRequest `protobuf:"bytes,7,opt,name=http_request,json=httpRequest,proto3,oneof"`
}

func (*Record_HttpRequest) isRecord_Request() {}

type isRecord_Response interface {
	isRecord_Response()
}

type Record_HttpResponse struct {
	HttpResponse *HTTPResponse `protobuf:"bytes,8,opt,name=http_response,json=httpResponse,proto3,oneof"`
}

func (*Record_HttpResponse) isRecord_Response() {}

type AuthenticationInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SessionId   string `protobuf:"bytes,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	IdpProvider string `protobuf:"bytes,2,opt,name=idp_provider,json=idpProvider,proto3" json:"idp_provider,omitempty"`
	IdpSubject  string `protobuf:"bytes,3,opt,name=idp_subject,json=idpSubject,proto3" json:"idp_subject,omitempty"`
}

func (x *AuthenticationInfo) Reset() {
	*x = AuthenticationInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_audit_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthenticationInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticationInfo) ProtoMessage() {}

func (x *AuthenticationInfo) ProtoReflect() protoreflect.Message {
	mi := &file_audit_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthenticationInfo.ProtoReflect.Descriptor instead.
func (*AuthenticationInfo) Descriptor() ([]byte, []int) {
	return file_audit_proto_rawDescGZIP(), []int{1}
}

func (x *AuthenticationInfo) GetSessionId() string {
	if x != nil {
		return x.SessionId
	}
	return ""
}

func (x *AuthenticationInfo) GetIdpProvider() string {
	if x != nil {
		return x.IdpProvider
	}
	return ""
}

func (x *AuthenticationInfo) GetIdpSubject() string {
	if x != nil {
		return x.IdpSubject
	}
	return ""
}

type HTTPRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id       string            `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Method   string            `protobuf:"bytes,2,opt,name=method,proto3" json:"method,omitempty"`
	Headers  map[string]string `protobuf:"bytes,3,rep,name=headers,proto3" json:"headers,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Path     string            `protobuf:"bytes,4,opt,name=path,proto3" json:"path,omitempty"`
	Host     string            `protobuf:"bytes,5,opt,name=host,proto3" json:"host,omitempty"`
	Scheme   string            `protobuf:"bytes,6,opt,name=scheme,proto3" json:"scheme,omitempty"`
	Query    string            `protobuf:"bytes,7,opt,name=query,proto3" json:"query,omitempty"`
	Fragment string            `protobuf:"bytes,8,opt,name=fragment,proto3" json:"fragment,omitempty"`
	Size     int64             `protobuf:"varint,9,opt,name=size,proto3" json:"size,omitempty"`
	Protocol string            `protobuf:"bytes,10,opt,name=protocol,proto3" json:"protocol,omitempty"`
	Body     string            `protobuf:"bytes,11,opt,name=body,proto3" json:"body,omitempty"`
}

func (x *HTTPRequest) Reset() {
	*x = HTTPRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_audit_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HTTPRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HTTPRequest) ProtoMessage() {}

func (x *HTTPRequest) ProtoReflect() protoreflect.Message {
	mi := &file_audit_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HTTPRequest.ProtoReflect.Descriptor instead.
func (*HTTPRequest) Descriptor() ([]byte, []int) {
	return file_audit_proto_rawDescGZIP(), []int{2}
}

func (x *HTTPRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *HTTPRequest) GetMethod() string {
	if x != nil {
		return x.Method
	}
	return ""
}

func (x *HTTPRequest) GetHeaders() map[string]string {
	if x != nil {
		return x.Headers
	}
	return nil
}

func (x *HTTPRequest) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *HTTPRequest) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *HTTPRequest) GetScheme() string {
	if x != nil {
		return x.Scheme
	}
	return ""
}

func (x *HTTPRequest) GetQuery() string {
	if x != nil {
		return x.Query
	}
	return ""
}

func (x *HTTPRequest) GetFragment() string {
	if x != nil {
		return x.Fragment
	}
	return ""
}

func (x *HTTPRequest) GetSize() int64 {
	if x != nil {
		return x.Size
	}
	return 0
}

func (x *HTTPRequest) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

func (x *HTTPRequest) GetBody() string {
	if x != nil {
		return x.Body
	}
	return ""
}

type HTTPResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StatusCode int32             `protobuf:"varint,1,opt,name=status_code,json=statusCode,proto3" json:"status_code,omitempty"`
	Headers    map[string]string `protobuf:"bytes,2,rep,name=headers,proto3" json:"headers,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Body       string            `protobuf:"bytes,3,opt,name=body,proto3" json:"body,omitempty"`
}

func (x *HTTPResponse) Reset() {
	*x = HTTPResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_audit_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HTTPResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HTTPResponse) ProtoMessage() {}

func (x *HTTPResponse) ProtoReflect() protoreflect.Message {
	mi := &file_audit_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HTTPResponse.ProtoReflect.Descriptor instead.
func (*HTTPResponse) Descriptor() ([]byte, []int) {
	return file_audit_proto_rawDescGZIP(), []int{3}
}

func (x *HTTPResponse) GetStatusCode() int32 {
	if x != nil {
		return x.StatusCode
	}
	return 0
}

func (x *HTTPResponse) GetHeaders() map[string]string {
	if x != nil {
		return x.Headers
	}
	return nil
}

func (x *HTTPResponse) GetBody() string {
	if x != nil {
		return x.Body
	}
	return ""
}

type Status struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Code    int32  `protobuf:"varint,1,opt,name=code,proto3" json:"code,omitempty"`
	Message string `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *Status) Reset() {
	*x = Status{}
	if protoimpl.UnsafeEnabled {
		mi := &file_audit_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Status) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Status) ProtoMessage() {}

func (x *Status) ProtoReflect() protoreflect.Message {
	mi := &file_audit_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Status.ProtoReflect.Descriptor instead.
func (*Status) Descriptor() ([]byte, []int) {
	return file_audit_proto_rawDescGZIP(), []int{4}
}

func (x *Status) GetCode() int32 {
	if x != nil {
		return x.Code
	}
	return 0
}

func (x *Status) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

var File_audit_proto protoreflect.FileDescriptor

var file_audit_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x61, 0x75, 0x64, 0x69, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x61,
	0x75, 0x64, 0x69, 0x74, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xa0, 0x04, 0x0a, 0x06, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x12, 0x27, 0x0a,
	0x0f, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x2e, 0x0a, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x52, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x4a, 0x0a, 0x13, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e,
	0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x61, 0x75, 0x64, 0x69, 0x74, 0x2e, 0x41, 0x75, 0x74, 0x68,
	0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x12,
	0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x6e,
	0x66, 0x6f, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65,
	0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x37, 0x0a, 0x0c,
	0x68, 0x74, 0x74, 0x70, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x12, 0x2e, 0x61, 0x75, 0x64, 0x69, 0x74, 0x2e, 0x48, 0x54, 0x54, 0x50, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x0b, 0x68, 0x74, 0x74, 0x70, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x3a, 0x0a, 0x0d, 0x68, 0x74, 0x74, 0x70, 0x5f, 0x72, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x61,
	0x75, 0x64, 0x69, 0x74, 0x2e, 0x48, 0x54, 0x54, 0x50, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x48, 0x01, 0x52, 0x0c, 0x68, 0x74, 0x74, 0x70, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x25, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x09, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x0d, 0x2e, 0x61, 0x75, 0x64, 0x69, 0x74, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x37, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x61, 0x75, 0x64,
	0x69, 0x74, 0x2e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x1a, 0x3b, 0x0a, 0x0d, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x09,
	0x0a, 0x07, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x42, 0x0a, 0x0a, 0x08, 0x72, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x77, 0x0a, 0x12, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x1d, 0x0a, 0x0a, 0x73,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x21, 0x0a, 0x0c, 0x69, 0x64,
	0x70, 0x5f, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0b, 0x69, 0x64, 0x70, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x12, 0x1f, 0x0a,
	0x0b, 0x69, 0x64, 0x70, 0x5f, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0a, 0x69, 0x64, 0x70, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x22, 0xe2,
	0x02, 0x0a, 0x0b, 0x48, 0x54, 0x54, 0x50, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e,
	0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x16,
	0x0a, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
	0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x12, 0x39, 0x0a, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x61, 0x75, 0x64, 0x69, 0x74, 0x2e,
	0x48, 0x54, 0x54, 0x50, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x48, 0x65, 0x61, 0x64,
	0x65, 0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x73, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x61, 0x74, 0x68, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x70, 0x61, 0x74, 0x68, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x63, 0x68,
	0x65, 0x6d, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x63, 0x68, 0x65, 0x6d,
	0x65, 0x12, 0x14, 0x0a, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x71, 0x75, 0x65, 0x72, 0x79, 0x12, 0x1a, 0x0a, 0x08, 0x66, 0x72, 0x61, 0x67, 0x6d,
	0x65, 0x6e, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x66, 0x72, 0x61, 0x67, 0x6d,
	0x65, 0x6e, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x04, 0x73, 0x69, 0x7a, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x63, 0x6f, 0x6c, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x63, 0x6f, 0x6c, 0x12, 0x12, 0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x0b, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x1a, 0x3a, 0x0a, 0x0c, 0x48, 0x65, 0x61, 0x64, 0x65,
	0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a,
	0x02, 0x38, 0x01, 0x22, 0xbb, 0x01, 0x0a, 0x0c, 0x48, 0x54, 0x54, 0x50, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x5f, 0x63,
	0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0a, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x3a, 0x0a, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73,
	0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x61, 0x75, 0x64, 0x69, 0x74, 0x2e, 0x48,
	0x54, 0x54, 0x50, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x48, 0x65, 0x61, 0x64,
	0x65, 0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x73, 0x12, 0x12, 0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x62, 0x6f, 0x64, 0x79, 0x1a, 0x3a, 0x0a, 0x0c, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x22, 0x36, 0x0a, 0x06, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x63,
	0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x12,
	0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x3c, 0x0a, 0x06, 0x49, 0x6e, 0x74,
	0x61, 0x6b, 0x65, 0x12, 0x32, 0x0a, 0x07, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x12, 0x0d,
	0x2e, 0x61, 0x75, 0x64, 0x69, 0x74, 0x2e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x1a, 0x16, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x45, 0x6d, 0x70, 0x74, 0x79, 0x28, 0x01, 0x42, 0x2d, 0x5a, 0x2b, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x70,
	0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x72, 0x63, 0x70,
	0x2f, 0x61, 0x75, 0x64, 0x69, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_audit_proto_rawDescOnce sync.Once
	file_audit_proto_rawDescData = file_audit_proto_rawDesc
)

func file_audit_proto_rawDescGZIP() []byte {
	file_audit_proto_rawDescOnce.Do(func() {
		file_audit_proto_rawDescData = protoimpl.X.CompressGZIP(file_audit_proto_rawDescData)
	})
	return file_audit_proto_rawDescData
}

var file_audit_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_audit_proto_goTypes = []interface{}{
	(*Record)(nil),              // 0: audit.Record
	(*AuthenticationInfo)(nil),  // 1: audit.AuthenticationInfo
	(*HTTPRequest)(nil),         // 2: audit.HTTPRequest
	(*HTTPResponse)(nil),        // 3: audit.HTTPResponse
	(*Status)(nil),              // 4: audit.Status
	nil,                         // 5: audit.Record.MetadataEntry
	nil,                         // 6: audit.HTTPRequest.HeadersEntry
	nil,                         // 7: audit.HTTPResponse.HeadersEntry
	(*timestamp.Timestamp)(nil), // 8: google.protobuf.Timestamp
	(*empty.Empty)(nil),         // 9: google.protobuf.Empty
}
var file_audit_proto_depIdxs = []int32{
	8, // 0: audit.Record.time:type_name -> google.protobuf.Timestamp
	1, // 1: audit.Record.authentication_info:type_name -> audit.AuthenticationInfo
	2, // 2: audit.Record.http_request:type_name -> audit.HTTPRequest
	3, // 3: audit.Record.http_response:type_name -> audit.HTTPResponse
	4, // 4: audit.Record.status:type_name -> audit.Status
	5, // 5: audit.Record.metadata:type_name -> audit.Record.MetadataEntry
	6, // 6: audit.HTTPRequest.headers:type_name -> audit.HTTPRequest.HeadersEntry
	7, // 7: audit.HTTPResponse.headers:type_name -> audit.HTTPResponse.HeadersEntry
	0, // 8: audit.Intake.Publish:input_type -> audit.Record
	9, // 9: audit.Intake.Publish:output_type -> google.protobuf.Empty
	9, // [9:10] is the sub-list for method output_type
	8, // [8:9] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_audit_proto_init() }
func file_audit_proto_init() {
	if File_audit_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_audit_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Record); i {
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
		file_audit_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthenticationInfo); i {
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
		file_audit_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HTTPRequest); i {
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
		file_audit_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HTTPResponse); i {
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
		file_audit_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Status); i {
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
	file_audit_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*Record_HttpRequest)(nil),
		(*Record_HttpResponse)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_audit_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_audit_proto_goTypes,
		DependencyIndexes: file_audit_proto_depIdxs,
		MessageInfos:      file_audit_proto_msgTypes,
	}.Build()
	File_audit_proto = out.File
	file_audit_proto_rawDesc = nil
	file_audit_proto_goTypes = nil
	file_audit_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// IntakeClient is the client API for Intake service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type IntakeClient interface {
	Publish(ctx context.Context, opts ...grpc.CallOption) (Intake_PublishClient, error)
}

type intakeClient struct {
	cc grpc.ClientConnInterface
}

func NewIntakeClient(cc grpc.ClientConnInterface) IntakeClient {
	return &intakeClient{cc}
}

func (c *intakeClient) Publish(ctx context.Context, opts ...grpc.CallOption) (Intake_PublishClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Intake_serviceDesc.Streams[0], "/audit.Intake/Publish", opts...)
	if err != nil {
		return nil, err
	}
	x := &intakePublishClient{stream}
	return x, nil
}

type Intake_PublishClient interface {
	Send(*Record) error
	CloseAndRecv() (*empty.Empty, error)
	grpc.ClientStream
}

type intakePublishClient struct {
	grpc.ClientStream
}

func (x *intakePublishClient) Send(m *Record) error {
	return x.ClientStream.SendMsg(m)
}

func (x *intakePublishClient) CloseAndRecv() (*empty.Empty, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(empty.Empty)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// IntakeServer is the server API for Intake service.
type IntakeServer interface {
	Publish(Intake_PublishServer) error
}

// UnimplementedIntakeServer can be embedded to have forward compatible implementations.
type UnimplementedIntakeServer struct {
}

func (*UnimplementedIntakeServer) Publish(Intake_PublishServer) error {
	return status.Errorf(codes.Unimplemented, "method Publish not implemented")
}

func RegisterIntakeServer(s *grpc.Server, srv IntakeServer) {
	s.RegisterService(&_Intake_serviceDesc, srv)
}

func _Intake_Publish_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(IntakeServer).Publish(&intakePublishServer{stream})
}

type Intake_PublishServer interface {
	SendAndClose(*empty.Empty) error
	Recv() (*Record, error)
	grpc.ServerStream
}

type intakePublishServer struct {
	grpc.ServerStream
}

func (x *intakePublishServer) SendAndClose(m *empty.Empty) error {
	return x.ServerStream.SendMsg(m)
}

func (x *intakePublishServer) Recv() (*Record, error) {
	m := new(Record)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _Intake_serviceDesc = grpc.ServiceDesc{
	ServiceName: "audit.Intake",
	HandlerType: (*IntakeServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Publish",
			Handler:       _Intake_Publish_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "audit.proto",
}
