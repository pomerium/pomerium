// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             (unknown)
// source: connect.proto

package connect

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	Connect_ReportUsage_FullMethodName = "/pomerium.zero.Connect/ReportUsage"
	Connect_Subscribe_FullMethodName   = "/pomerium.zero.Connect/Subscribe"
)

// ConnectClient is the client API for Connect service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// Connect service is used to maintain a persistent connection between the
// Pomerium Core and Zero Cloud and receive messages from the cloud.
type ConnectClient interface {
	// ReportUsage reports usage.
	ReportUsage(ctx context.Context, in *ReportUsageRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// Subscribe is used to send a stream of messages from the Zero Cloud to the
	// Pomerium Core in managed mode.
	Subscribe(ctx context.Context, in *SubscribeRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Message], error)
}

type connectClient struct {
	cc grpc.ClientConnInterface
}

func NewConnectClient(cc grpc.ClientConnInterface) ConnectClient {
	return &connectClient{cc}
}

func (c *connectClient) ReportUsage(ctx context.Context, in *ReportUsageRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, Connect_ReportUsage_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *connectClient) Subscribe(ctx context.Context, in *SubscribeRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Message], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Connect_ServiceDesc.Streams[0], Connect_Subscribe_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[SubscribeRequest, Message]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Connect_SubscribeClient = grpc.ServerStreamingClient[Message]

// ConnectServer is the server API for Connect service.
// All implementations should embed UnimplementedConnectServer
// for forward compatibility.
//
// Connect service is used to maintain a persistent connection between the
// Pomerium Core and Zero Cloud and receive messages from the cloud.
type ConnectServer interface {
	// ReportUsage reports usage.
	ReportUsage(context.Context, *ReportUsageRequest) (*emptypb.Empty, error)
	// Subscribe is used to send a stream of messages from the Zero Cloud to the
	// Pomerium Core in managed mode.
	Subscribe(*SubscribeRequest, grpc.ServerStreamingServer[Message]) error
}

// UnimplementedConnectServer should be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedConnectServer struct{}

func (UnimplementedConnectServer) ReportUsage(context.Context, *ReportUsageRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReportUsage not implemented")
}
func (UnimplementedConnectServer) Subscribe(*SubscribeRequest, grpc.ServerStreamingServer[Message]) error {
	return status.Errorf(codes.Unimplemented, "method Subscribe not implemented")
}
func (UnimplementedConnectServer) testEmbeddedByValue() {}

// UnsafeConnectServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ConnectServer will
// result in compilation errors.
type UnsafeConnectServer interface {
	mustEmbedUnimplementedConnectServer()
}

func RegisterConnectServer(s grpc.ServiceRegistrar, srv ConnectServer) {
	// If the following call pancis, it indicates UnimplementedConnectServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Connect_ServiceDesc, srv)
}

func _Connect_ReportUsage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReportUsageRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ConnectServer).ReportUsage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Connect_ReportUsage_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ConnectServer).ReportUsage(ctx, req.(*ReportUsageRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Connect_Subscribe_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(SubscribeRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ConnectServer).Subscribe(m, &grpc.GenericServerStream[SubscribeRequest, Message]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Connect_SubscribeServer = grpc.ServerStreamingServer[Message]

// Connect_ServiceDesc is the grpc.ServiceDesc for Connect service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Connect_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "pomerium.zero.Connect",
	HandlerType: (*ConnectServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ReportUsage",
			Handler:    _Connect_ReportUsage_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Subscribe",
			Handler:       _Connect_Subscribe_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "connect.proto",
}
