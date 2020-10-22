package identity

import (
	"encoding/json"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/pkg/protoutil"
)

// Claims are JWT claims.
type Claims map[string]interface{}

// UnmarshalJSON unmarshals the raw json data into the claims object.
func (claims *Claims) UnmarshalJSON(data []byte) error {
	if *claims == nil {
		*claims = make(map[string]interface{})
	}

	var m map[string]interface{}
	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}
	for k, v := range m {
		(*claims)[k] = v
	}
	return nil
}

// Claims takes the claims data and fills v.
func (claims Claims) Claims(v interface{}) error {
	bs, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	return json.Unmarshal(bs, v)
}

// ToAnyMap converts the claims into a map of string => any.
func (claims Claims) ToAnyMap() map[string]*anypb.Any {
	m := map[string]*anypb.Any{}
	for k, v := range claims {
		m[k] = protoutil.ToAny(v)
	}
	return m
}
