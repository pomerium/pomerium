package cryptutil // import "github.com/pomerium/pomerium/internal/cryptutil"

// MockEncoder MockCSRFStore is a mock implementation of Cipher.
type MockEncoder struct {
	MarshalResponse string
	MarshalError    error
	UnmarshalError  error
}

// Marshal is a mock implementation of MockEncoder.
func (mc MockEncoder) Marshal(i interface{}) (string, error) {
	return mc.MarshalResponse, mc.MarshalError
}

// Unmarshal is a mock implementation of MockEncoder.
func (mc MockEncoder) Unmarshal(s string, i interface{}) error {
	return mc.UnmarshalError
}
