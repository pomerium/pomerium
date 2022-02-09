// Package identity contains protobuf types for identity management.
package identity

import (
	"crypto/sha256"

	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/encoding/base58"
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
