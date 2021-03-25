package cryptutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyEncryptionKey(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		kek, err := GenerateKeyEncryptionKey()
		require.NoError(t, err)
		ciphertext, err := kek.Public().Encrypt([]byte("HELLO WORLD"))
		require.NoError(t, err)
		plaintext, err := kek.Decrypt(ciphertext)
		require.NoError(t, err)
		require.Equal(t, []byte("HELLO WORLD"), plaintext)
	})
	t.Run("dek", func(t *testing.T) {
		dek, err := GenerateDataEncryptionKey()
		require.NoError(t, err)
		kek, err := GenerateKeyEncryptionKey()
		require.NoError(t, err)
		ciphertext, err := kek.Public().EncryptDataEncryptionKey(dek)
		require.NoError(t, err)
		dek2, err := kek.DecryptDataEncryptionKey(ciphertext)
		require.NoError(t, err)
		require.Equal(t, dek, dek2)
	})
	t.Run("invalid key", func(t *testing.T) {
		t.Run("private", func(t *testing.T) {
			kek, err := NewPrivateKeyEncryptionKey("TEST", []byte("NOT BIG ENOUGH"))
			require.Nil(t, kek)
			require.Error(t, err)
		})
		t.Run("public", func(t *testing.T) {
			kek, err := NewPublicKeyEncryptionKey("TEST", []byte("NOT BIG ENOUGH"))
			require.Nil(t, kek)
			require.Error(t, err)
		})
	})
	t.Run("bad data", func(t *testing.T) {
		kek, err := GenerateKeyEncryptionKey()
		require.NoError(t, err)
		ciphertext, err := kek.Public().Encrypt([]byte("HELLO WORLD"))
		require.NoError(t, err)
		ciphertext[3]++
		plaintext, err := kek.Decrypt(ciphertext)
		require.Error(t, err)
		require.Nil(t, plaintext)
	})
}
