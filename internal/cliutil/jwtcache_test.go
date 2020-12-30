package cliutil

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
)

func TestLocalJWTCache(t *testing.T) {
	c := &LocalJWTCache{
		dir: filepath.Join(os.TempDir(), uuid.New().String()),
	}

	err := os.MkdirAll(c.dir, 0o755)
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = os.RemoveAll(c.dir) }()

	t.Run("NotFound", func(t *testing.T) {
		_, err := c.LoadJWT("NOTFOUND")
		assert.Equal(t, ErrNotFound, err)
	})
	t.Run("Invalid", func(t *testing.T) {
		err := c.StoreJWT("INVALID", "INVALID")
		if !assert.NoError(t, err) {
			return
		}
		_, err = c.LoadJWT("INVALID")
		assert.Equal(t, ErrInvalid, err)
	})
	t.Run("Expired", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if !assert.NoError(t, err) {
			return
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS512, Key: privateKey}, nil)
		if !assert.NoError(t, err) {
			return
		}

		object, err := signer.Sign([]byte(`{"exp": ` + fmt.Sprint(time.Now().Add(-time.Second).Unix()) + `}`))
		if !assert.NoError(t, err) {
			return
		}

		rawJWT, err := object.CompactSerialize()
		if !assert.NoError(t, err) {
			return
		}

		err = c.StoreJWT("EXPIRED", rawJWT)
		if !assert.NoError(t, err) {
			return
		}

		_, err = c.LoadJWT("EXPIRED")
		assert.Equal(t, ErrExpired, err)
	})
}
