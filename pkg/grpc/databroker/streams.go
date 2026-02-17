package databroker

import "google.golang.org/grpc"

//go:generate go tool -modfile ../../../internal/tools/go.mod go.uber.org/mock/mockgen -package mock_databroker -destination ./mock_databroker/streams.go . SyncLatestClient,SyncClient

// SyncLatestClient is the streaming client interface for SyncLatest.
type SyncLatestClient interface {
	grpc.ServerStreamingClient[SyncLatestResponse]
}

// SyncClient is the streaming client interface for Sync.
type SyncClient interface {
	grpc.ServerStreamingClient[SyncResponse]
}
