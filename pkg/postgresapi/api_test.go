package postgresapi

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSessionBindingProofMessage(t *testing.T) {
	message, err := SessionBindingProofMessage(" DB.EXAMPLE.COM. ", "raw-handle", []byte("certificate-der"))
	require.NoError(t, err)
	require.Equal(t,
		"706f6d657269756d2e636f6d2f6e61746976652d706f7374677265732f73657373696f6e2d62696e64696e672f763100"+
			"0000000e64622e6578616d706c652e636f6d"+
			"91a15223b28793ca4054346e571f823c9748397baaed78da8310714766633089"+
			"03f48c90a8e6886eab083a748a07cdbbae80c034c57ae76a11635ad852d913e3",
		hex.EncodeToString(message))

	canonical, err := SessionBindingProofMessage("db.example.com", "raw-handle", []byte("certificate-der"))
	require.NoError(t, err)
	require.Equal(t, message, canonical)

	for name, call := range map[string]func() ([]byte, error){
		"route": func() ([]byte, error) {
			return SessionBindingProofMessage("other.example.com", "raw-handle", []byte("certificate-der"))
		},
		"handle": func() ([]byte, error) {
			return SessionBindingProofMessage("db.example.com", "other-handle", []byte("certificate-der"))
		},
		"certificate": func() ([]byte, error) {
			return SessionBindingProofMessage("db.example.com", "raw-handle", []byte("other-certificate"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			other, err := call()
			require.NoError(t, err)
			require.NotEqual(t, message, other)
		})
	}
}

func TestSessionBindingProofMessageRejectsIncompleteInputs(t *testing.T) {
	for name, call := range map[string]func() ([]byte, error){
		"route":       func() ([]byte, error) { return SessionBindingProofMessage("", "handle", []byte("certificate")) },
		"handle":      func() ([]byte, error) { return SessionBindingProofMessage("db.example.com", "", []byte("certificate")) },
		"certificate": func() ([]byte, error) { return SessionBindingProofMessage("db.example.com", "handle", nil) },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := call()
			require.Error(t, err)
		})
	}
}
