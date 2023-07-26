package autocert

import (
	"bytes"

	lru "github.com/hashicorp/golang-lru/v2"
)

type ocspCache struct {
	*lru.Cache[string, []byte]
}

func newOCSPCache(size int) (*ocspCache, error) {
	c, err := lru.New[string, []byte](size)
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
	if bytes.Equal(current, ocspResp) {
		return false
	}
	_ = c.Add(key, ocspResp)
	return true
}
