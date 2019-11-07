package encoding // import "github.com/pomerium/pomerium/internal/encoding"

// MockEncoder MockCSRFStore is a mock implementation of Cipher.
type MockEncoder struct {
	MarshalResponse []byte
	MarshalError    error
	UnmarshalError  error
}

// Marshal is a mock implementation of MockEncoder.
func (mc MockEncoder) Marshal(i interface{}) ([]byte, error) {
	return mc.MarshalResponse, mc.MarshalError
}

// Unmarshal is a mock implementation of MockEncoder.
func (mc MockEncoder) Unmarshal(s []byte, i interface{}) error {
	return mc.UnmarshalError
}
