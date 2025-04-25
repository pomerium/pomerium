package mcp

import (
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/bufbuild/protovalidate-go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

const (
	CodeTypeAuthorization = oauth21proto.CodeType_CODE_TYPE_AUTHORIZATION
	CodeTypeRefresh       = oauth21proto.CodeType_CODE_TYPE_REFRESH
	CodeTypeAccess        = oauth21proto.CodeType_CODE_TYPE_ACCESS
)

func CreateCode(
	typ oauth21proto.CodeType,
	id string,
	expires time.Time,
	ad string,
	cipher cipher.AEAD,
) (string, error) {
	if expires.IsZero() {
		return "", fmt.Errorf("validate: zero expiration")
	}

	v := oauth21proto.Code{
		Id:        id,
		ExpiresAt: timestamppb.New(expires),
		GrantType: typ,
	}

	err := protovalidate.Validate(&v)
	if err != nil {
		return "", fmt.Errorf("validate: %w", err)
	}

	b, err := proto.Marshal(&v)
	if err != nil {
		return "", err
	}

	ciphertext := cryptutil.Encrypt(cipher, b, getAD(ad, typ))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptCode(
	typ oauth21proto.CodeType,
	code string,
	cipher cipher.AEAD,
	ad string,
	now time.Time,
) (*oauth21proto.Code, error) {
	b, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	plaintext, err := cryptutil.Decrypt(cipher, b, getAD(ad, typ))
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	var v oauth21proto.Code
	err = proto.Unmarshal(plaintext, &v)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if v.ExpiresAt == nil {
		return nil, fmt.Errorf("expiration is nil")
	}
	if v.ExpiresAt.AsTime().Before(now) {
		return nil, fmt.Errorf("code expired")
	}
	return &v, nil
}

func getAD(ad string, typ oauth21proto.CodeType) []byte {
	return []byte(fmt.Sprintf("%s:%s", ad, typ.String()))
}
