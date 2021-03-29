// Package crypt contains cryptographic protobuf messages.
package crypt

import (
	"encoding/base64"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/encoding/protojson"
)

// MarshalZerologObject fills the zerolog event fields.
func (x *SealedMessage) MarshalZerologObject(evt *zerolog.Event) {
	evt.Str("@type", "type.googleapis.com/pomerium.crypt.SealedMessage").
		Str("key_id", x.GetKeyId()).
		Str("data_encryption_key", base64.StdEncoding.EncodeToString(x.GetDataEncryptionKey())).
		Str("message_type", x.GetMessageType()).
		Str("encrypted_message", base64.StdEncoding.EncodeToString(x.GetEncryptedMessage()))
}

// UnmarshalFromRawZerolog unmarshals a raw zerolog object into the sealed message.
func (x *SealedMessage) UnmarshalFromRawZerolog(raw []byte) error {
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: true,
	}
	return opts.Unmarshal(raw, x)
}
