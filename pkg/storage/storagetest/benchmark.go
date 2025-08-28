package storagetest

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

func BenchmarkPut(b *testing.B, backend storage.Backend) {
	b.Helper()

	data := protoutil.NewAnyString(strings.Repeat("x", 128))
	b.ResetTimer()
	for is := range iterutil.Chunk(iterutil.Count(b.N), 8) {
		records := make([]*databrokerpb.Record, 0, len(is))
		for _, i := range is {
			records = append(records, &databrokerpb.Record{
				Type: fmt.Sprintf("t-%d", i%16),
				Id:   fmt.Sprintf("i-%d", i),
				Data: data,
			})
		}
		_, err := backend.Put(b.Context(), records)
		require.NoError(b, err)
	}
}
