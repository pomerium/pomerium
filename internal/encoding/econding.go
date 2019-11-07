package encoding // import "github.com/pomerium/pomerium/internal/encoding"

// MarshalUnmarshaler can both Marshal and Unmarshal a struct into and from a set of bytes.
type MarshalUnmarshaler interface {
	Marshaler
	Unmarshaler
}

// Marshaler encodes a struct into a set of bytes.
type Marshaler interface {
	Marshal(interface{}) ([]byte, error)
}

// Unmarshaler decodes a set of bytes and returns a struct.
type Unmarshaler interface {
	Unmarshal([]byte, interface{}) error
}
