package databroker

import (
	"context"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

type ClientGetter interface {
	GetDataBrokerServiceClient() DataBrokerServiceClient
}

func NewStaticClientGetter(client DataBrokerServiceClient) ClientGetter {
	return staticClientGetter{
		client: client,
	}
}

type staticClientGetter struct {
	client DataBrokerServiceClient
}

func (w staticClientGetter) GetDataBrokerServiceClient() DataBrokerServiceClient {
	return w.client
}

type databrokerClientKey struct{}

func WithDatabrokerClient(ctx context.Context, client dataBrokerServiceClient) context.Context {
	return context.WithValue(ctx, databrokerClientKey{}, client)
}

func GetDatabrokerClient(ctx context.Context) DataBrokerServiceClient {
	c, ok := ctx.Value(databrokerClientKey{}).(DataBrokerServiceClient)
	if !ok {
		c = &nilClient{
			defaultErr: status.Error(codes.Unavailable, "not yet initialized"),
		}
	}
	return c
}

type nilClient struct {
	defaultErr error
}

var _ DataBrokerServiceClient = (*nilClient)(nil)

// AcquireLease acquires a distributed mutex lease.
func (n *nilClient) AcquireLease(_ context.Context, _ *AcquireLeaseRequest, _ ...grpc.CallOption) (*AcquireLeaseResponse, error) {
	return nil, n.defaultErr
}

// Clear removes all records from the databroker.
func (n *nilClient) Clear(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*ClearResponse, error) {
	return nil, n.defaultErr
}

// Get gets a record.
func (n *nilClient) Get(_ context.Context, _ *GetRequest, _ ...grpc.CallOption) (*GetResponse, error) {
	return nil, n.defaultErr
}

// ListTypes lists all the known record types.
func (n *nilClient) ListTypes(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*ListTypesResponse, error) {
	return nil, n.defaultErr
}

// Put saves a record.
func (n *nilClient) Put(_ context.Context, _ *PutRequest, _ ...grpc.CallOption) (*PutResponse, error) {
	return nil, n.defaultErr
}

// Patch updates specific fields of an existing record.
func (n *nilClient) Patch(_ context.Context, _ *PatchRequest, _ ...grpc.CallOption) (*PatchResponse, error) {
	return nil, n.defaultErr
}

// Query queries for records.
func (n *nilClient) Query(_ context.Context, _ *QueryRequest, _ ...grpc.CallOption) (*QueryResponse, error) {
	return nil, n.defaultErr
}

// ReleaseLease releases a distributed mutex lease.
func (n *nilClient) ReleaseLease(_ context.Context, _ *ReleaseLeaseRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, n.defaultErr
}

// RenewLease renews a distributed mutex lease.
func (n *nilClient) RenewLease(_ context.Context, _ *RenewLeaseRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, n.defaultErr
}

// ServerInfo returns information about the databroker server.
func (n *nilClient) ServerInfo(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*ServerInfoResponse, error) {
	return nil, n.defaultErr
}

// SetOptions sets the options for a type in the databroker.
func (n *nilClient) SetOptions(_ context.Context, _ *SetOptionsRequest, _ ...grpc.CallOption) (*SetOptionsResponse, error) {
	return nil, n.defaultErr
}

// Sync streams changes to records after the specified version.
func (n *nilClient) Sync(_ context.Context, _ *SyncRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[SyncResponse], error) {
	return nil, n.defaultErr
}

// SyncLatest streams the latest version of every record.
func (n *nilClient) SyncLatest(_ context.Context, _ *SyncLatestRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[SyncLatestResponse], error) {
	return nil, n.defaultErr
}
