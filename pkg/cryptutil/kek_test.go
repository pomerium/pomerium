package cryptutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyEncryptionKey(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		kek, err := GenerateKeyEncryptionKey()
		require.NoError(t, err)
		assert.NotEqual(t, make([]byte, KeyEncryptionKeySize), kek.data)
		ciphertext, err := kek.Public().Encrypt([]byte("HELLO WORLD"))
		require.NoError(t, err)
		plaintext, err := kek.Decrypt(ciphertext)
		require.NoError(t, err)
		require.Equal(t, []byte("HELLO WORLD"), plaintext)
	})
	t.Run("anonymous", func(t *testing.T) {
		kek, err := GenerateKeyEncryptionKey()
		require.NoError(t, err)
		kekPublic, err := NewPublicKeyEncryptionKey(kek.Public().KeyBytes())
		require.NoError(t, err)
		ciphertext, err := kekPublic.Encrypt([]byte("HELLO WORLD"))
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
	t.Run("ID", func(t *testing.T) {
		kek, err := GenerateKeyEncryptionKey()
		require.NoError(t, err)
		assert.Equal(t, kek.Public().id, kek.ID())
	})
	t.Run("KeyBytes", func(t *testing.T) {
		private, err := GenerateKeyEncryptionKey()
		require.NoError(t, err)
		assert.Equal(t, private.data[:], private.KeyBytes())
		public := private.Public()
		assert.Equal(t, public.data[:], public.KeyBytes())
	})
	t.Run("GetKeyEncryptionKeyID", func(t *testing.T) {
		id := GetKeyEncryptionKeyID([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31})
		assert.Equal(t, "7nfE5LQBMyWq3tmZsDiK5EaT2nMPMvFJWDDEZWWLoni", id)
	})
	t.Run("invalid key", func(t *testing.T) {
		t.Run("private", func(t *testing.T) {
			kek, err := NewPrivateKeyEncryptionKey([]byte("NOT BIG ENOUGH"))
			require.Nil(t, kek)
			require.Error(t, err)
		})
		t.Run("public", func(t *testing.T) {
			kek, err := NewPublicKeyEncryptionKey([]byte("NOT BIG ENOUGH"))
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
