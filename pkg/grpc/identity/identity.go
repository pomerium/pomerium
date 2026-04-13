// Package identity contains protobuf types for identity management.
package identity

import (
	"crypto/sha256"

	"github.com/jxskiss/base62"
	"google.golang.org/protobuf/proto"
)

// Clone clones the Provider.
func (x *Provider) Clone() *Provider {
	return proto.Clone(x).(*Provider)
}

// Hash computes a sha256 hash of the provider's identity-determining fields.
// It excludes fields that do not affect which IdP session is used:
//   - Id (derived from the hash itself)
//   - AccessTokenAllowedAudiences (per-route post-auth filtering, not session identity)
func (x *Provider) Hash() string {
	tmp := x.Clone()
	tmp.Id = ""
	tmp.AccessTokenAllowedAudiences = nil
	bs, _ := proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	}.Marshal(tmp)
	h := sha256.Sum256(bs)
	return base62.EncodeToString(h[:])
}
