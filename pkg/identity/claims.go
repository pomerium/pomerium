package identity

import (
	"encoding/json"
	"fmt"
	"reflect"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/protoutil"
)

// SessionClaims are claims that are attached to a session so we can store the raw id token.
type SessionClaims struct {
	Claims
	RawIDToken string
}

// SetRawIDToken sets the raw id token.
func (claims *SessionClaims) SetRawIDToken(rawIDToken string) {
	claims.RawIDToken = rawIDToken
}

// Claims are JWT claims.
type Claims map[string]any

// NewClaimsFromRaw creates a new Claims map from a map of raw messages.
func NewClaimsFromRaw(raw map[string]json.RawMessage) Claims {
	claims := make(Claims)
	for k, rawv := range raw {
		var v any
		if err := json.Unmarshal(rawv, &v); err == nil {
			claims[k] = v
		}
	}
	return claims
}

// UnmarshalJSON unmarshals the raw json data into the claims object.
func (claims *Claims) UnmarshalJSON(data []byte) error {
	if *claims == nil {
		*claims = make(Claims)
	}

	var m map[string]any
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
func (claims Claims) Claims(v any) error {
	bs, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	return json.Unmarshal(bs, v)
}

// Flatten flattens the claims to a FlattenedClaims map. For example:
//
//	{ "a": { "b": { "c": 12345 } } } => { "a.b.c": [12345] }
func (claims Claims) Flatten() FlattenedClaims {
	flattened := make(FlattenedClaims)
	for k, v := range claims {
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Map:
			subClaims := make(Claims)
			iter := rv.MapRange()
			for iter.Next() {
				subClaims[fmt.Sprint(iter.Key().Interface())] = iter.Value().Interface()
			}
			for sk, sv := range subClaims.Flatten() {
				flattened[k+"."+sk] = sv
			}
		case reflect.Slice:
			slc := make([]any, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				slc[i] = rv.Index(i).Interface()
			}
			flattened[k] = slc
		default:
			flattened[k] = []any{v}
		}
	}
	return flattened
}

// ToAnyMap converts the claims into a map of string => any.
func (claims Claims) ToAnyMap() map[string]*anypb.Any {
	m := map[string]*anypb.Any{}
	for k, v := range claims {
		m[k] = protoutil.ToAny(v)
	}
	return m
}

// FlattenedClaims are a set claims flattened into a single-level map.
type FlattenedClaims map[string][]any

// NewFlattenedClaimsFromPB creates a new FlattenedClaims from the protobuf struct type.
func NewFlattenedClaimsFromPB(m map[string]*structpb.ListValue) FlattenedClaims {
	claims := make(FlattenedClaims)
	if m == nil {
		return claims
	}
	bs, _ := json.Marshal(m)
	_ = json.Unmarshal(bs, &claims)
	return claims
}

// ToPB converts the flattened claims into a protobuf type.
func (claims FlattenedClaims) ToPB() map[string]*structpb.ListValue {
	if claims == nil {
		return nil
	}
	m := make(map[string]*structpb.ListValue, len(claims))
	for k, vs := range claims {
		svs := make([]*structpb.Value, len(vs))
		for i, v := range vs {
			svs[i] = protoutil.ToStruct(v)
		}
		m[k] = &structpb.ListValue{Values: svs}
	}
	return m
}

// UnmarshalJSON unmarshals JSON into the flattened claims.
func (claims *FlattenedClaims) UnmarshalJSON(data []byte) error {
	var unflattened Claims
	err := json.Unmarshal(data, &unflattened)
	if err != nil {
		return err
	}

	if *claims == nil {
		*claims = make(FlattenedClaims)
	}
	for k, v := range unflattened.Flatten() {
		(*claims)[k] = v
	}
	return nil
}
