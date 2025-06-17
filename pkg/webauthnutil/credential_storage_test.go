package webauthnutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/webauthn"
)

type mockDataBrokerServiceClient struct {
	databroker.DataBrokerServiceClient

	get func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error)
	put func(ctx context.Context, in *databroker.PutRequest, opts ...grpc.CallOption) (*databroker.PutResponse, error)
}

func (m mockDataBrokerServiceClient) Get(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
	return m.get(ctx, in, opts...)
}

func (m mockDataBrokerServiceClient) Put(ctx context.Context, in *databroker.PutRequest, opts ...grpc.CallOption) (*databroker.PutResponse, error) {
	return m.put(ctx, in, opts...)
}

func TestCredentialStorage(t *testing.T) {
	m := map[string]*databroker.Record{}
	client := &mockDataBrokerServiceClient{
		get: func(_ context.Context, in *databroker.GetRequest, _ ...grpc.CallOption) (*databroker.GetResponse, error) {
			record, ok := m[in.GetType()+"/"+in.GetId()]
			if !ok {
				return nil, status.Error(codes.NotFound, "record not found")
			}
			return &databroker.GetResponse{
				Record: record,
			}, nil
		},
		put: func(_ context.Context, in *databroker.PutRequest, _ ...grpc.CallOption) (*databroker.PutResponse, error) {
			for _, record := range in.GetRecords() {
				m[record.GetType()+"/"+record.GetId()] = record
			}
			return &databroker.PutResponse{
				Records: in.GetRecords(),
			}, nil
		},
	}
	storage := NewCredentialStorage(client)
	_, err := storage.GetCredential(t.Context(), []byte{0, 1, 2, 3, 4})
	assert.ErrorIs(t, err, webauthn.ErrCredentialNotFound)
	err = storage.SetCredential(t.Context(), &webauthn.Credential{
		ID: []byte{0, 1, 2, 3, 4},
	})
	assert.NoError(t, err)
	c, err := storage.GetCredential(t.Context(), []byte{0, 1, 2, 3, 4})
	assert.NoError(t, err)
	assert.Equal(t, []byte{0, 1, 2, 3, 4}, c.ID)
}
