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
	for b.Loop() {
		GetFileNameWithBytesHash("example.crt", bs)
	}
}
