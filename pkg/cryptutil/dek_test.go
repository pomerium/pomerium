package cryptutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDataEncryptionKey(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		dek, err := GenerateDataEncryptionKey()
		require.NoError(t, err)
		ciphertext := dek.Encrypt([]byte("HELLO WORLD"))
		plaintext, err := dek.Decrypt(ciphertext)
		require.NoError(t, err)
		require.Equal(t, []byte("HELLO WORLD"), plaintext)
	})
	t.Run("roundtrip string", func(t *testing.T) {
		dek, err := GenerateDataEncryptionKey()
		require.NoError(t, err)
		ciphertext := dek.EncryptString(("HELLO WORLD"))
		plaintext, err := dek.DecryptString(ciphertext)
		require.NoError(t, err)
		require.Equal(t, ("HELLO WORLD"), plaintext)
	})
	t.Run("KeyBytes", func(t *testing.T) {
		dek, err := GenerateDataEncryptionKey()
		require.NoError(t, err)
		assert.Equal(t, dek.data[:], dek.KeyBytes())
	})
	t.Run("invalid key", func(t *testing.T) {
		dek, err := NewDataEncryptionKey([]byte("NOT BIG ENOUGH"))
		require.Nil(t, dek)
		require.Error(t, err)
	})
	t.Run("bad data", func(t *testing.T) {
		dek, err := GenerateDataEncryptionKey()
		require.NoError(t, err)
		ciphertext := dek.Encrypt([]byte("HELLO WORLD"))
		ciphertext[3]++
		plaintext, err := dek.Decrypt(ciphertext)
		require.Error(t, err)
		require.Nil(t, plaintext)
	})
}

func TestDataEncryptionKeyCache(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		cache := NewDataEncryptionKeyCache()
		kek, err := GenerateKeyEncryptionKey()
		require.NoError(t, err)
		dek, err := GenerateDataEncryptionKey()
		require.NoError(t, err)
		ciphertext, err := kek.Public().EncryptDataEncryptionKey(dek)
		require.NoError(t, err)
		cache.Put(ciphertext, dek)
		dek2, ok := cache.Get(ciphertext)
		require.True(t, ok)
		require.Equal(t, dek, dek2)
	})
	t.Run("eviction", func(t *testing.T) {
		cache := NewDataEncryptionKeyCache()
		kek, err := GenerateKeyEncryptionKey()
		require.NoError(t, err)

		dek, err := GenerateDataEncryptionKey()
		require.NoError(t, err)
		ciphertext, err := kek.Public().EncryptDataEncryptionKey(dek)
		require.NoError(t, err)
		cache.Put(ciphertext, dek)

		for i := 0; i < DataEncryptionKeyCacheSize; i++ {
			dek, err := GenerateDataEncryptionKey()
			require.NoError(t, err)
			ciphertext, err := kek.Public().EncryptDataEncryptionKey(dek)
			require.NoError(t, err)
			cache.Put(ciphertext, dek)
		}

		dek2, ok := cache.Get(ciphertext)
		require.False(t, ok, "should evict the least recently used DEK")
		require.Nil(t, dek2)
	})
}
