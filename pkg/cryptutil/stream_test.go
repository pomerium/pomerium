package cryptutil_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestEncryptStream(t *testing.T) {
	t.Parallel()

	plaintext := make([]byte, 4048*2.5)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	// cipher
	c, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
	require.NoError(t, err)

	// encrypt
	encrypted := &bytes.Buffer{}
	encrypter, err := cryptutil.EncryptStream(bytes.NewBuffer(plaintext), c)
	require.NoError(t, err)
	_, err = io.Copy(encrypted, encrypter)
	require.NoError(t, err)

	// decrypt
	decrypted := &bytes.Buffer{}
	decrypter, err := cryptutil.DecryptStream(encrypted, c)
	require.NoError(t, err)
	_, err = decrypted.ReadFrom(decrypter)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted.Bytes())
}
