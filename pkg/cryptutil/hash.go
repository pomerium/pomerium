package cryptutil

import (
	"crypto/hmac"
	"crypto/sha512"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/proto"
)

// Hash generates a hash of data using HMAC-SHA-512/256. The tag is intended to
// be a natural-language string describing the purpose of the hash, such as
// "hash file for lookup key" or "master secret to client secret".  It serves
// as an HMAC "key" and ensures that different purposes will have different
// hash output. This function is NOT suitable for hashing passwords.
func Hash(tag string, data []byte) []byte {
	h := hmac.New(sha512.New512_256, []byte(tag))
	h.Write(data)
	return h.Sum(nil)
}

// HashPassword generates a bcrypt hash of the password using work factor 14.
func HashPassword(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, 14)
}

// CheckPasswordHash securely compares a bcrypt hashed password with its possible
// plaintext equivalent.  Returns nil on success, or an error on failure.
func CheckPasswordHash(hash, password []byte) error {
	return bcrypt.CompareHashAndPassword(hash, password)
}

// HashProto hashes a protobuf message. It sets `Deterministic` to true to ensure
// the encoded message is always the same. (ie map order is lexographic)
func HashProto(msg proto.Message) []byte {
	opts := proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	}
	bs, _ := opts.Marshal(msg)
	return Hash("proto", bs)
}
