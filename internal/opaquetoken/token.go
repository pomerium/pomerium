// Package opaquetoken mints and validates opaque tokens: unguessable strings
// that dereference to a databroker record.
//
// A token carries no meaning of its own. It is an AEAD-sealed [Payload] holding
// a record id, an expiration, a [Type] tag saying what the token may be
// presented for, and optionally the record version observed at issuance time.
// Only a holder of the sealing key can read or forge one.
package opaquetoken

import (
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

const (
	TypeAuthorization = Type_TYPE_AUTHORIZATION
	TypeRefresh       = Type_TYPE_REFRESH
	TypeAccess        = Type_TYPE_ACCESS
)

// Seal mints a token of type typ referencing the databroker record id, valid
// until expires. The token is sealed with cipher, bound to the associated data
// ad, and base64-encoded. Open must be called with the same type and associated
// data.
//
// recordVersion embeds the databroker record version of the referenced record,
// which the reader can replay as a minimum-version hint (read-your-writes). A
// zero version embeds no hint.
func Seal(
	typ Type,
	id string,
	expires time.Time,
	ad string,
	cipher cipher.AEAD,
	recordVersion uint64,
) (string, error) {
	if expires.IsZero() {
		return "", fmt.Errorf("validate: zero expiration")
	}

	v := Payload{
		Id:            id,
		ExpiresAt:     timestamppb.New(expires),
		Type:          typ,
		RecordVersion: recordVersion,
	}

	err := protovalidate.Validate(&v)
	if err != nil {
		return "", fmt.Errorf("validate: %w", err)
	}

	b, err := proto.Marshal(&v)
	if err != nil {
		return "", err
	}

	ciphertext := cryptutil.Encrypt(cipher, b, []byte(ad))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Open unseals token and returns its payload, rejecting it if it was not sealed
// by cipher with the associated data ad, if it was not minted with type typ, or
// if it expired before now.
func Open(
	typ Type,
	token string,
	cipher cipher.AEAD,
	ad string,
	now time.Time,
) (*Payload, error) {
	b, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	plaintext, err := cryptutil.Decrypt(cipher, b, []byte(ad))
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	var v Payload
	err = proto.Unmarshal(plaintext, &v)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	err = protovalidate.Validate(&v)
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}
	if v.Type != typ {
		return nil, fmt.Errorf("token type mismatch: expected %v, got %v", typ, v.Type)
	}
	if v.ExpiresAt.AsTime().Before(now) {
		return nil, fmt.Errorf("token expired")
	}
	return &v, nil
}
