package autocert

import (
	"bytes"

	lru "github.com/hashicorp/golang-lru"
)

type ocspCache struct {
	*lru.Cache
}

func newOCSPCache(size int) (*ocspCache, error) {
	c, err := lru.New(size)
	if err != nil {
		return nil, err
	}
	return &ocspCache{c}, nil
}

// updated checks if OCSP response for this certificate was updated
func (c ocspCache) updated(key string, ocspResp []byte) bool {
	current, there := c.Get(key)
	if !there {
		_ = c.Add(key, ocspResp)
		return false // to avoid triggering reload first time we see this response
	}
	if bytes.Equal(current.([]byte), ocspResp) {
		return false
	}
	_ = c.Add(key, ocspResp)
	return true
}
