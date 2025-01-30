// Package hashutil provides NON-CRYPTOGRAPHIC utility functions for hashing.
//
//nolint:errcheck
package hashutil

import (
	"encoding/binary"

	"github.com/cespare/xxhash/v2"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/zeebo/xxh3"
)

// MustHash returns the xxhash of an arbitrary value or struct. Returns 0
// on error.
// NOT SUITABLE FOR CRYTOGRAPHIC HASHING.
func MustHash(v any) uint64 {
	hash, err := Hash(v)
	if err != nil {
		hash = 0
	}
	return hash
}

// Hash returns the xxhash of an arbitrary value or struct.
// NOT SUITABLE FOR CRYTOGRAPHIC HASHING.
func Hash(v any) (uint64, error) {
	opts := &hashstructure.HashOptions{
		Hasher: xxh3.New(),
	}
	return hashstructure.Hash(v, hashstructure.FormatV2, opts)
}

type Digest struct {
	xxhash.Digest
}

func NewDigest() *Digest {
	var d Digest
	d.Reset()
	return &d
}

// WriteStringWithLen writes the string's length, then its contents to the hash.
func (d *Digest) WriteStringWithLen(s string) {
	d.WriteInt32(int32(len(s)))
	d.WriteString(s)
}

// WriteStringWithLen writes the byte array's length, then its contents to
// the hash.
func (d *Digest) WriteWithLen(b []byte) {
	d.WriteInt32(int32(len(b)))
	d.Write(b)
}

// WriteBool writes a single byte (1 or 0) to the hash.
func (d *Digest) WriteBool(b bool) {
	if b {
		d.Write([]byte{1})
	} else {
		d.Write([]byte{0})
	}
}

// WriteUint32 writes a uint16 to the hash.
func (d *Digest) WriteUint16(t uint16) {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], t)
	d.Write(buf[:])
}

// WriteUint32 writes a uint32 to the hash.
func (d *Digest) WriteUint32(t uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], t)
	d.Write(buf[:])
}

// WriteUint32 writes a uint64 to the hash.
func (d *Digest) WriteUint64(t uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], t)
	d.Write(buf[:])
}

// WriteInt16 writes an int16 to the hash.
func (d *Digest) WriteInt16(t int16) {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], uint16(t))
	d.Write(buf[:])
}

// WriteInt32 writes an int32 to the hash.
func (d *Digest) WriteInt32(t int32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(t))
	d.Write(buf[:])
}

// WriteInt64 writes an int64 to the hash.
func (d *Digest) WriteInt64(t int64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(t))
	d.Write(buf[:])
}

// WriteStringPtr writes one byte (1 or 0) indicating whether the pointer is non-nil,
// followed by the value if present.
func (d *Digest) WriteStringPtr(t *string) {
	if t == nil {
		d.Write([]byte{0})
	} else {
		d.Write([]byte{1})
		d.WriteString(*t)
	}
}

// WriteStringPtr writes one byte (1 or 0) indicating whether the pointer is non-nil,
// followed by the string's length and value, if present.
func (d *Digest) WriteStringPtrWithLen(t *string) {
	if t == nil {
		d.Write([]byte{0})
	} else {
		d.Write([]byte{1})
		d.WriteStringWithLen(*t)
	}
}

// WriteBoolPtr writes one byte (1 or 0) indicating whether the pointer is non-nil,
// followed by the value if present.
func (d *Digest) WriteBoolPtr(t *bool) {
	if t == nil {
		d.Write([]byte{0})
	} else {
		d.Write([]byte{1})
		d.WriteBool(*t)
	}
}

// WriteUint16Ptr writes one byte (1 or 0) indicating whether the pointer is non-nil,
// followed by the value if present.
func (d *Digest) WriteUint16Ptr(t *uint16) {
	if t == nil {
		d.Write([]byte{0})
	} else {
		d.Write([]byte{1})
		d.WriteUint16(*t)
	}
}

// WriteUint32Ptr writes one byte (1 or 0) indicating whether the pointer is non-nil,
// followed by the value if present.
func (d *Digest) WriteUint32Ptr(t *uint32) {
	if t == nil {
		d.Write([]byte{0})
	} else {
		d.Write([]byte{1})
		d.WriteUint32(*t)
	}
}

// WriteUint64Ptr writes one byte (1 or 0) indicating whether the pointer is non-nil,
// followed by the value if present.
func (d *Digest) WriteUint64Ptr(t *uint64) {
	if t == nil {
		d.Write([]byte{0})
	} else {
		d.Write([]byte{1})
		d.WriteUint64(*t)
	}
}

// WriteInt16Ptr writes one byte (1 or 0) indicating whether the pointer is non-nil,
// followed by the value if present.
func (d *Digest) WriteInt16Ptr(t *int16) {
	if t == nil {
		d.Write([]byte{0})
	} else {
		d.Write([]byte{1})
		d.WriteInt16(*t)
	}
}

// WriteInt32Ptr writes one byte (1 or 0) indicating whether the pointer is non-nil,
// followed by the value if present.
func (d *Digest) WriteInt32Ptr(t *int32) {
	if t == nil {
		d.Write([]byte{0})
	} else {
		d.Write([]byte{1})
		d.WriteInt32(*t)
	}
}

// WriteInt64Ptr writes one byte (1 or 0) indicating whether the pointer is non-nil,
// followed by the value if present.
func (d *Digest) WriteInt64Ptr(t *int64) {
	if t == nil {
		d.Write([]byte{0})
	} else {
		d.Write([]byte{1})
		d.WriteInt64(*t)
	}
}
