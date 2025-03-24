package grpctest

import (
	"path/filepath"
	"testing"

	"github.com/pomerium/pomerium/pkg/grpc"
)

func TemporaryOutboundAddress(t *testing.T) string {
	original := grpc.OutboundAddress
	t.Cleanup(func() { grpc.OutboundAddress = original })
	grpc.OutboundAddress = filepath.Join(t.TempDir(), "pomerium-outbound.sock")
	return grpc.OutboundAddress
}
