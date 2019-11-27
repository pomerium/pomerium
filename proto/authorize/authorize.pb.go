// Code generated by protoc-gen-go. DO NOT EDIT.
// source: authorize.proto

package authorize

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Identity struct {
	// request context
	Route string `protobuf:"bytes,1,opt,name=route,proto3" json:"route,omitempty"`
	// user context
	User   string   `protobuf:"bytes,2,opt,name=user,proto3" json:"user,omitempty"`
	Email  string   `protobuf:"bytes,3,opt,name=email,proto3" json:"email,omitempty"`
	Groups []string `protobuf:"bytes,4,rep,name=groups,proto3" json:"groups,omitempty"`
	// user context
	ImpersonateEmail     string   `protobuf:"bytes,5,opt,name=impersonate_email,json=impersonateEmail,proto3" json:"impersonate_email,omitempty"`
	ImpersonateGroups    []string `protobuf:"bytes,6,rep,name=impersonate_groups,json=impersonateGroups,proto3" json:"impersonate_groups,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Identity) Reset()         { *m = Identity{} }
func (m *Identity) String() string { return proto.CompactTextString(m) }
func (*Identity) ProtoMessage()    {}
func (*Identity) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffbc3c71370bee9a, []int{0}
}

func (m *Identity) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Identity.Unmarshal(m, b)
}
func (m *Identity) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Identity.Marshal(b, m, deterministic)
}
func (m *Identity) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Identity.Merge(m, src)
}
func (m *Identity) XXX_Size() int {
	return xxx_messageInfo_Identity.Size(m)
}
func (m *Identity) XXX_DiscardUnknown() {
	xxx_messageInfo_Identity.DiscardUnknown(m)
}

var xxx_messageInfo_Identity proto.InternalMessageInfo

func (m *Identity) GetRoute() string {
	if m != nil {
		return m.Route
	}
	return ""
}

func (m *Identity) GetUser() string {
	if m != nil {
		return m.User
	}
	return ""
}

func (m *Identity) GetEmail() string {
	if m != nil {
		return m.Email
	}
	return ""
}

func (m *Identity) GetGroups() []string {
	if m != nil {
		return m.Groups
	}
	return nil
}

func (m *Identity) GetImpersonateEmail() string {
	if m != nil {
		return m.ImpersonateEmail
	}
	return ""
}

func (m *Identity) GetImpersonateGroups() []string {
	if m != nil {
		return m.ImpersonateGroups
	}
	return nil
}

type AuthorizeReply struct {
	IsValid              bool     `protobuf:"varint,1,opt,name=is_valid,json=isValid,proto3" json:"is_valid,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AuthorizeReply) Reset()         { *m = AuthorizeReply{} }
func (m *AuthorizeReply) String() string { return proto.CompactTextString(m) }
func (*AuthorizeReply) ProtoMessage()    {}
func (*AuthorizeReply) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffbc3c71370bee9a, []int{1}
}

func (m *AuthorizeReply) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AuthorizeReply.Unmarshal(m, b)
}
func (m *AuthorizeReply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AuthorizeReply.Marshal(b, m, deterministic)
}
func (m *AuthorizeReply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuthorizeReply.Merge(m, src)
}
func (m *AuthorizeReply) XXX_Size() int {
	return xxx_messageInfo_AuthorizeReply.Size(m)
}
func (m *AuthorizeReply) XXX_DiscardUnknown() {
	xxx_messageInfo_AuthorizeReply.DiscardUnknown(m)
}

var xxx_messageInfo_AuthorizeReply proto.InternalMessageInfo

func (m *AuthorizeReply) GetIsValid() bool {
	if m != nil {
		return m.IsValid
	}
	return false
}

type IsAdminReply struct {
	IsAdmin              bool     `protobuf:"varint,1,opt,name=is_admin,json=isAdmin,proto3" json:"is_admin,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *IsAdminReply) Reset()         { *m = IsAdminReply{} }
func (m *IsAdminReply) String() string { return proto.CompactTextString(m) }
func (*IsAdminReply) ProtoMessage()    {}
func (*IsAdminReply) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffbc3c71370bee9a, []int{2}
}

func (m *IsAdminReply) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_IsAdminReply.Unmarshal(m, b)
}
func (m *IsAdminReply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_IsAdminReply.Marshal(b, m, deterministic)
}
func (m *IsAdminReply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IsAdminReply.Merge(m, src)
}
func (m *IsAdminReply) XXX_Size() int {
	return xxx_messageInfo_IsAdminReply.Size(m)
}
func (m *IsAdminReply) XXX_DiscardUnknown() {
	xxx_messageInfo_IsAdminReply.DiscardUnknown(m)
}

var xxx_messageInfo_IsAdminReply proto.InternalMessageInfo

func (m *IsAdminReply) GetIsAdmin() bool {
	if m != nil {
		return m.IsAdmin
	}
	return false
}

func init() {
	proto.RegisterType((*Identity)(nil), "authorize.Identity")
	proto.RegisterType((*AuthorizeReply)(nil), "authorize.AuthorizeReply")
	proto.RegisterType((*IsAdminReply)(nil), "authorize.IsAdminReply")
}

func init() { proto.RegisterFile("authorize.proto", fileDescriptor_ffbc3c71370bee9a) }

var fileDescriptor_ffbc3c71370bee9a = []byte{
	// 264 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x51, 0xbd, 0x4e, 0xc3, 0x30,
	0x10, 0x6e, 0x68, 0x9b, 0x26, 0x27, 0xc4, 0xcf, 0x81, 0x20, 0x65, 0xaa, 0x3c, 0x15, 0x55, 0x74,
	0x80, 0x89, 0x81, 0xa1, 0x03, 0x42, 0x5d, 0x33, 0xb0, 0x56, 0x46, 0xb1, 0xe0, 0xa4, 0x24, 0x8e,
	0x6c, 0x07, 0xa9, 0x3c, 0x00, 0x8f, 0xc5, 0xb3, 0xa1, 0x5c, 0xd2, 0xc4, 0x48, 0x6c, 0xf9, 0x7e,
	0x73, 0x77, 0x86, 0x53, 0x59, 0xbb, 0x0f, 0x6d, 0xe8, 0x4b, 0xad, 0x2b, 0xa3, 0x9d, 0xc6, 0xb8,
	0x27, 0xc4, 0x4f, 0x00, 0xd1, 0x36, 0x53, 0xa5, 0x23, 0xb7, 0xc7, 0x4b, 0x98, 0x1a, 0x5d, 0x3b,
	0x95, 0x04, 0x8b, 0x60, 0x19, 0xa7, 0x2d, 0x40, 0x84, 0x49, 0x6d, 0x95, 0x49, 0x8e, 0x98, 0xe4,
	0xef, 0xc6, 0xa9, 0x0a, 0x49, 0x79, 0x32, 0x6e, 0x9d, 0x0c, 0xf0, 0x0a, 0xc2, 0x77, 0xa3, 0xeb,
	0xca, 0x26, 0x93, 0xc5, 0x78, 0x19, 0xa7, 0x1d, 0xc2, 0x15, 0x9c, 0x53, 0x51, 0x29, 0x63, 0x75,
	0x29, 0x9d, 0xda, 0xb5, 0xc9, 0x29, 0x27, 0xcf, 0x3c, 0xe1, 0x99, 0x4b, 0xee, 0x00, 0x7d, 0x73,
	0x57, 0x18, 0x72, 0xa1, 0x5f, 0xf3, 0xc2, 0x82, 0x58, 0xc1, 0xc9, 0xe6, 0xb0, 0x4d, 0xaa, 0xaa,
	0x7c, 0x8f, 0x73, 0x88, 0xc8, 0xee, 0x3e, 0x65, 0x4e, 0x19, 0x2f, 0x12, 0xa5, 0x33, 0xb2, 0xaf,
	0x0d, 0x14, 0xb7, 0x70, 0xbc, 0xb5, 0x9b, 0xac, 0xa0, 0xd2, 0xb7, 0xca, 0x86, 0x18, 0xac, 0xac,
	0xdf, 0x7f, 0x07, 0x00, 0x7d, 0xb1, 0xc1, 0x27, 0x88, 0x7b, 0x84, 0x17, 0xeb, 0xe1, 0xa2, 0x87,
	0xe3, 0xdd, 0xcc, 0x3d, 0xf2, 0xef, 0x44, 0x62, 0x84, 0x8f, 0x30, 0xeb, 0x7e, 0xfc, 0x7f, 0xf8,
	0xda, 0x27, 0xbd, 0x09, 0xc5, 0xe8, 0x2d, 0xe4, 0x37, 0x7b, 0xf8, 0x0d, 0x00, 0x00, 0xff, 0xff,
	0x6d, 0x2f, 0xa0, 0x1b, 0xc6, 0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// AuthorizerClient is the client API for Authorizer service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AuthorizerClient interface {
	Authorize(ctx context.Context, in *Identity, opts ...grpc.CallOption) (*AuthorizeReply, error)
	IsAdmin(ctx context.Context, in *Identity, opts ...grpc.CallOption) (*IsAdminReply, error)
}

type authorizerClient struct {
	cc *grpc.ClientConn
}

func NewAuthorizerClient(cc *grpc.ClientConn) AuthorizerClient {
	return &authorizerClient{cc}
}

func (c *authorizerClient) Authorize(ctx context.Context, in *Identity, opts ...grpc.CallOption) (*AuthorizeReply, error) {
	out := new(AuthorizeReply)
	err := c.cc.Invoke(ctx, "/authorize.Authorizer/Authorize", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authorizerClient) IsAdmin(ctx context.Context, in *Identity, opts ...grpc.CallOption) (*IsAdminReply, error) {
	out := new(IsAdminReply)
	err := c.cc.Invoke(ctx, "/authorize.Authorizer/IsAdmin", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthorizerServer is the server API for Authorizer service.
type AuthorizerServer interface {
	Authorize(context.Context, *Identity) (*AuthorizeReply, error)
	IsAdmin(context.Context, *Identity) (*IsAdminReply, error)
}

// UnimplementedAuthorizerServer can be embedded to have forward compatible implementations.
type UnimplementedAuthorizerServer struct {
}

func (*UnimplementedAuthorizerServer) Authorize(ctx context.Context, req *Identity) (*AuthorizeReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Authorize not implemented")
}
func (*UnimplementedAuthorizerServer) IsAdmin(ctx context.Context, req *Identity) (*IsAdminReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IsAdmin not implemented")
}

func RegisterAuthorizerServer(s *grpc.Server, srv AuthorizerServer) {
	s.RegisterService(&_Authorizer_serviceDesc, srv)
}

func _Authorizer_Authorize_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Identity)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthorizerServer).Authorize(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/authorize.Authorizer/Authorize",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthorizerServer).Authorize(ctx, req.(*Identity))
	}
	return interceptor(ctx, in, info, handler)
}

func _Authorizer_IsAdmin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Identity)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthorizerServer).IsAdmin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/authorize.Authorizer/IsAdmin",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthorizerServer).IsAdmin(ctx, req.(*Identity))
	}
	return interceptor(ctx, in, info, handler)
}

var _Authorizer_serviceDesc = grpc.ServiceDesc{
	ServiceName: "authorize.Authorizer",
	HandlerType: (*AuthorizerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Authorize",
			Handler:    _Authorizer_Authorize_Handler,
		},
		{
			MethodName: "IsAdmin",
			Handler:    _Authorizer_IsAdmin_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "authorize.proto",
}
