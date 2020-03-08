package cryptutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestSign(t *testing.T) {
	message := []byte("Hello, world!")

	key, err := NewSigningKey()
	if err != nil {
		t.Error(err)
		return
	}

	signature, err := Sign(message, key)
	if err != nil {
		t.Error(err)
		return
	}

	if !Verify(message, signature, &key.PublicKey) {
		t.Error("signature was not correct")
		return
	}

	message[0] ^= 0xff
	if Verify(message, signature, &key.PublicKey) {
		t.Error("signature was good for altered message")
	}
}

func TestSignWithP384(t *testing.T) {
	message := []byte("Hello, world!")

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}

	signature, err := Sign(message, key)
	if err != nil {
		t.Error(err)
		return
	}

	if !Verify(message, signature, &key.PublicKey) {
		t.Error("signature was not correct")
		return
	}

	message[0] ^= 0xff
	if Verify(message, signature, &key.PublicKey) {
		t.Error("signature was good for altered message")
	}
}
