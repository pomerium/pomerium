package recording

import grpc "google.golang.org/grpc"

//go:generate go tool -modfile ../../../internal/tools/go.mod go.uber.org/mock/mockgen -package mock_recording -destination ./mock_recording/streams.go . RecordingRecordClient

// RecordingServiceClient is the streaming client interface for Record.
type RecordingRecordClient interface {
	grpc.ServerStreamingClient[RecordingData]
}
