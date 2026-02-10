package cryptutil

import (
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/volatiletech/null/v9"
)

func SignServiceAccount(
	key []byte,
	id string,
	subject string,
	issuedAt time.Time,
	expiresAt null.Time,
) (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("error creating JWT signer: %w", err)
	}

	var claims struct {
		jwt.Claims
	}
	claims.ID = id
	claims.Subject = subject
	claims.IssuedAt = jwt.NewNumericDate(issuedAt)
	claims.NotBefore = jwt.NewNumericDate(issuedAt)
	if expiresAt.IsValid() {
		claims.Expiry = jwt.NewNumericDate(expiresAt.Time)
	}

	rawJWT, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("error creating signed JWT: %w", err)
	}
	return rawJWT, nil
}
