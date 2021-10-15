package webauthnutil

import (
	"time"

	"github.com/google/uuid"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// NewEnrollmentToken creates a new EnrollmentToken.
func NewEnrollmentToken(key []byte, ttl time.Duration, deviceEnrollmentID string) (string, error) {
	id, err := uuid.Parse(deviceEnrollmentID)
	if err != nil {
		return "", err
	}

	secureToken := cryptutil.GenerateSecureToken(key, time.Now().Add(ttl), cryptutil.Token(id))
	return secureToken.String(), nil
}

// ParseAndVerifyEnrollmentToken parses and verifies an enrollment token
func ParseAndVerifyEnrollmentToken(key []byte, rawEnrollmentToken string) (string, error) {
	secureToken, ok := cryptutil.SecureTokenFromString(rawEnrollmentToken)
	if !ok {
		return "", cryptutil.ErrInvalid
	}

	err := secureToken.Verify(key, time.Now())
	if err != nil {
		return "", err
	}

	return secureToken.Token().UUID().String(), nil
}
