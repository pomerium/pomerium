package webauthnutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEnrollmentToken(t *testing.T) {
	t.Parallel()

	key := []byte{1, 2, 3}
	deviceEnrollmentID := "19be0131-184e-4873-acab-2be79321c30b"
	token, err := NewEnrollmentToken(key, time.Second*30, deviceEnrollmentID)
	assert.NoError(t, err)
	id, err := ParseAndVerifyEnrollmentToken(key, token)
	assert.NoError(t, err)
	assert.Equal(t, deviceEnrollmentID, id)
}
