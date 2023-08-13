package reconciler

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestReadRecords(t *testing.T) {

	dir := t.TempDir()
	fd, err := os.CreateTemp(dir, "config")
	require.NoError(t, err)
	t.Cleanup(func() { _ = fd.Close() })

	err = writeSampleRecords(fd)
	require.NoError(t, err)

	_, err = fd.Seek(0, io.SeekStart)
	require.NoError(t, err)

	records, err := ReadBundleRecords(fd)
	require.NoError(t, err)
	require.Len(t, records, 1)
}

func writeSampleRecords(dst io.Writer) error {
	var marshalOpts = protodelim.MarshalOptions{
		MarshalOptions: proto.MarshalOptions{
			AllowPartial:  false,
			Deterministic: true,
			UseCachedSize: false,
		},
	}

	cfg := protoutil.NewAny(&config.Config{
		Routes: []*config.Route{
			{
				From: "https://from.example.com",
				To:   []string{"https://to.example.com"},
			},
		},
	})
	rec := &databroker.Record{
		Id:   "config",
		Type: cfg.GetTypeUrl(),
		Data: cfg,
	}
	_, err := marshalOpts.MarshalTo(dst, rec)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return nil
}
