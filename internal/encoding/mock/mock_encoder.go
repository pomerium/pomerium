package mock // import "github.com/pomerium/pomerium/internal/encoding/mock"

import (
	"github.com/pomerium/pomerium/internal/encoding"
)

var _ encoding.MarshalUnmarshaler = &Encoder{}
var _ encoding.Marshaler = &Encoder{}
var _ encoding.Unmarshaler = &Encoder{}

// Encoder MockCSRFStore is a mock implementation of Cipher.
type Encoder struct {
	MarshalResponse []byte
	MarshalError    error
	UnmarshalError  error
}

// Marshal is a mock implementation of Encoder.
func (mc Encoder) Marshal(i interface{}) ([]byte, error) {
	return mc.MarshalResponse, mc.MarshalError
}

// Unmarshal is a mock implementation of Encoder.
func (mc Encoder) Unmarshal(s []byte, i interface{}) error {
	return mc.UnmarshalError
}
