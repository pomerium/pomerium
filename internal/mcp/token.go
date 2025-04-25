package mcp

import (
	"crypto/cipher"
	"fmt"

	"github.com/pomerium/pomerium/internal/oauth21"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func CheckPKCE(
	codeChallengeMethod string,
	codeChallenge string,
	codeVerifier string,
) error {
	if codeChallengeMethod == "" || codeChallengeMethod == "plain" {
		if !oauth21.VerifyPKCEPlain(codeVerifier, codeChallenge) {
			return fmt.Errorf("plain: code verifier does not match code challenge")
		}
	} else if codeChallengeMethod == "S256" {
		if !oauth21.VerifyPKCES256(codeVerifier, codeChallenge) {
			return fmt.Errorf("S256: code verifier does not match code challenge")
		}
	} else {
		return fmt.Errorf("unsupported code challenge method: %s", codeChallengeMethod)
	}

	return nil
}

func CreateAccessToken(src *session.Session, cipher cipher.AEAD) (string, error) {
	return CreateCode(CodeTypeAccess, src.Id, src.ExpiresAt.AsTime(), "", cipher)
}
