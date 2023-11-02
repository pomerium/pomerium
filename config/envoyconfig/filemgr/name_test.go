package filemgr

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkGetFileNameWithBytesHash(b *testing.B) {
	bs := make([]byte, 1024*128)
	_, err := rand.Read(bs)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetFileNameWithBytesHash("example.crt", bs)
	}
}
