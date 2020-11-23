package cryptutil

import (
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeAndDecodeAccessToken(t *testing.T) {
	plaintext := []byte("my plain text value")

	key := NewKey()
	c, err := NewAEADCipher(key)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	ciphertext := Encrypt(c, plaintext, nil)

	if reflect.DeepEqual(plaintext, ciphertext) {
		t.Fatalf("plaintext is not encrypted plaintext:%v ciphertext:%x", plaintext, ciphertext)
	}

	diffKey, err := NewAEADCipher(NewKey())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// key mismatch
	_, err = Decrypt(diffKey, ciphertext, nil)
	assert.Error(t, err)

	// bad data size
	_, err = Decrypt(c, []byte("oh"), nil)
	assert.Error(t, err)

	// good
	got, err := Decrypt(c, ciphertext, nil)
	assert.NoError(t, err)
	assert.Equal(t, got, plaintext)
}

func TestNewAEADCipher(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		secret  []byte
		wantErr bool
	}{
		{"simple 32 byte key", NewKey(), false},
		{"key too short", []byte("what is entropy"), true},
		{"key too long", []byte(NewRandomStringN(33)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAEADCipher(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAEADCipher() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func BenchmarkAEADCipher(b *testing.B) {
	plaintext := []byte("my plain text value")

	key := NewKey()
	c, err := NewAEADCipher(key)
	if !assert.NoError(b, err) {
		return
	}

	ciphertext := Encrypt(c, plaintext, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(c, ciphertext, nil)
	}
}

func TestNewAEADCipherFromBase64(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		s       string
		wantErr bool
	}{
		{"simple 32 byte key", base64.StdEncoding.EncodeToString(NewKey()), false},
		{"key too short", base64.StdEncoding.EncodeToString([]byte("what is entropy")), true},
		{"key too long", NewRandomStringN(33), true},
		{"bad base 64", string(NewKey()), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAEADCipherFromBase64(tt.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAEADCipherFromBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
