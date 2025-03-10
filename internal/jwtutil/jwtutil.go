// Package jwtutil contains functions for working with JWTs.
package jwtutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

// Claims represent claims in a JWT.
type Claims map[string]any

// UnmarshalJSON implements a custom unmarshaller for claims data.
func (claims *Claims) UnmarshalJSON(raw []byte) error {
	dst := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	err := dec.Decode(&dst)
	if err != nil {
		return err
	}
	*claims = Claims(dst)
	return nil
}

// registered claims

// GetIssuer gets the iss claim.
func (claims Claims) GetIssuer() (issuer string, ok bool) {
	return claims.GetString("iss")
}

// GetSubject gets the sub claim.
func (claims Claims) GetSubject() (subject string, ok bool) {
	return claims.GetString("sub")
}

// GetAudience gets the aud claim.
func (claims Claims) GetAudience() (audiences []string, ok bool) {
	return claims.GetStringSlice("aud")
}

// GetExpirationTime gets the exp claim.
func (claims Claims) GetExpirationTime() (expirationTime time.Time, ok bool) {
	return claims.GetNumericDate("exp")
}

// GetNotBefore gets the nbf claim.
func (claims Claims) GetNotBefore() (notBefore time.Time, ok bool) {
	return claims.GetNumericDate("nbf")
}

// GetIssuedAt gets the iat claim.
func (claims Claims) GetIssuedAt() (issuedAt time.Time, ok bool) {
	return claims.GetNumericDate("iat")
}

// GetJWTID gets the jti claim.
func (claims Claims) GetJWTID() (jwtID string, ok bool) {
	return claims.GetString("jti")
}

// custom claims

// GetUserID returns the oid or sub claim.
func (claims Claims) GetUserID() (userID string, ok bool) {
	if oid, ok := claims.GetString("oid"); ok {
		return oid, true
	}

	if sub, ok := claims.GetSubject(); ok {
		return sub, true
	}

	return "", false
}

// GetNumericDate returns the claim as a numeric date.
func (claims Claims) GetNumericDate(name string) (tm time.Time, ok bool) {
	if claims == nil {
		return tm, false
	}

	raw, ok := claims[name]
	if !ok {
		return tm, false
	}

	switch v := raw.(type) {
	case float32:
		return time.Unix(int64(v), 0), true
	case float64:
		return time.Unix(int64(v), 0), true
	case int64:
		return time.Unix(v, 0), true
	case int32:
		return time.Unix(int64(v), 0), true
	case int16:
		return time.Unix(int64(v), 0), true
	case int8:
		return time.Unix(int64(v), 0), true
	case int:
		return time.Unix(int64(v), 0), true
	case uint64:
		return time.Unix(int64(v), 0), true
	case uint32:
		return time.Unix(int64(v), 0), true
	case uint16:
		return time.Unix(int64(v), 0), true
	case uint8:
		return time.Unix(int64(v), 0), true
	case uint:
		return time.Unix(int64(v), 0), true
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			if f, err := v.Float64(); err == nil {
				i = int64(f)
			}
		}
		if err != nil {
			return tm, false
		}
		return time.Unix(i, 0), true
	}

	return tm, false
}

// GetString returns the claim as a string.
func (claims Claims) GetString(name string) (value string, ok bool) {
	raw, ok := claims[name]
	if !ok {
		return value, false
	}

	return toString(raw), true
}

// GetStringSlice returns the claim as a slice of strings.
func (claims Claims) GetStringSlice(name string) (values []string, ok bool) {
	raw, ok := claims[name]
	if !ok {
		return nil, false
	}

	return toStringSlice(raw), true
}

func toString(data any) string {
	switch v := data.(type) {
	case string:
		return v
	}
	return fmt.Sprint(data)
}

func toStringSlice(obj any) []string {
	v := reflect.ValueOf(obj)
	switch v.Kind() {
	case reflect.Slice:
		vs := make([]string, v.Len())
		for i := 0; i < v.Len(); i++ {
			vs[i] = toString(v.Index(i).Interface())
		}
		return vs
	}

	return []string{toString(obj)}
}
