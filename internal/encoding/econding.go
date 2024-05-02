// Package encoding defines interfaces shared by other packages that
// convert data to and from byte-level and textual representations.
package encoding

// MarshalUnmarshaler can both Marshal and Unmarshal a struct into and from a set of bytes.
type MarshalUnmarshaler interface {
	Marshaler
	Unmarshaler
}

// Marshaler encodes a struct into a set of bytes.
type Marshaler interface {
	Marshal(any) ([]byte, error)
}

// Unmarshaler decodes a set of bytes and returns a struct.
type Unmarshaler interface {
	Unmarshal([]byte, any) error
}
