// Package identity contains protobuf types for identity management.
package identity

import (
	"crypto/sha256"

	"github.com/akamensky/base58"
	"google.golang.org/protobuf/proto"
)

// Clone clones the Provider.
func (x *Provider) Clone() *Provider {
	return proto.Clone(x).(*Provider)
}

// Hash computes a sha256 hash of the provider's fields. It excludes the Id field.
func (x *Provider) Hash() string {
	tmp := x.Clone()
	tmp.Id = ""
	bs, _ := proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	}.Marshal(tmp)
	h := sha256.Sum256(bs)
	return base58.Encode(h[:])
}
