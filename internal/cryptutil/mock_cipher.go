package cryptutil // import "github.com/pomerium/pomerium/internal/cryptutil"

// MockCipher MockCSRFStore is a mock implementation of Cipher.
type MockCipher struct {
	EncryptResponse []byte
	EncryptError    error
	DecryptResponse []byte
	DecryptError    error
	MarshalResponse string
	MarshalError    error
	UnmarshalError  error
}

// Encrypt is a mock implementation of MockCipher.
func (mc MockCipher) Encrypt(b []byte) ([]byte, error) { return mc.EncryptResponse, mc.EncryptError }

// Decrypt is a mock implementation of MockCipher.
func (mc MockCipher) Decrypt(b []byte) ([]byte, error) { return mc.DecryptResponse, mc.DecryptError }

// Marshal is a mock implementation of MockCipher.
func (mc MockCipher) Marshal(i interface{}) (string, error) {
	return mc.MarshalResponse, mc.MarshalError
}

// Unmarshal is a mock implementation of MockCipher.
func (mc MockCipher) Unmarshal(s string, i interface{}) error {
	return mc.UnmarshalError
}
