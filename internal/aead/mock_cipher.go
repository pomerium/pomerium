package aead // import "github.com/pomerium/pomerium/internal/aead"

import (
	"encoding/json"
)

// MockCipher is a mock of the cipher interface
type MockCipher struct {
	MarshalError   error
	MarshalString  string
	UnmarshalError error
	UnmarshalBytes []byte
}

// Encrypt returns an empty byte array and nil
func (mc *MockCipher) Encrypt([]byte) ([]byte, error) {
	return []byte{}, nil
}

// Decrypt returns an empty byte array and nil
func (mc *MockCipher) Decrypt([]byte) ([]byte, error) {
	return []byte{}, nil
}

// Marshal returns the marshal string and marsha error
func (mc *MockCipher) Marshal(interface{}) (string, error) {
	return mc.MarshalString, mc.MarshalError
}

// Unmarshal unmarshals the unmarshal bytes to be set in s and returns the unmarshal error
func (mc *MockCipher) Unmarshal(b string, s interface{}) error {
	json.Unmarshal(mc.UnmarshalBytes, s)
	return mc.UnmarshalError
}
