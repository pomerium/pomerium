package cryptutil_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/volatiletech/null/v9"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestSignServiceAccount(t *testing.T) {
	t.Parallel()

	issuedAt := time.Date(2026, time.February, 5, 13, 41, 0, 0, time.UTC)
	jwt, err := cryptutil.SignServiceAccount(
		bytes.Repeat([]byte{0x01}, 32),
		"ID",
		"SUBJECT",
		issuedAt,
		null.TimeFrom(issuedAt.Add(365*24*time.Hour)),
	)
	assert.NoError(t, err)
	assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4MDE4MzQ4NjAsImlhdCI6MTc3MDI5ODg2MCwianRpIjoiSUQiLCJuYmYiOjE3NzAyOTg4NjAsInN1YiI6IlNVQkpFQ1QifQ.XEdUSyeyUk2784Po8ABkUyEcSRS9HGlgIRUyjfnnWIg", jwt)
}
