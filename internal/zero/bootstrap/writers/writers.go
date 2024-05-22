package writers

import (
	"context"
	"crypto/cipher"
	"fmt"
	"net/url"
	"sync"

	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
)

type ConfigWriter interface {
	WriteConfig(ctx context.Context, src *cluster_api.BootstrapConfig, cipher cipher.AEAD) error
}

// A WriterBuilder creates and initializes a new ConfigWriter previously
// obtained from LoadWriter.
type WriterBuilder func(uri *url.URL) (ConfigWriter, error)

var writers sync.Map

func RegisterBuilder(scheme string, wb WriterBuilder) {
	writers.Store(scheme, wb)
}

func LoadBuilder(scheme string) WriterBuilder {
	if writer, ok := writers.Load(scheme); ok {
		return writer.(WriterBuilder)
	}
	return nil
}

func NewForURI(uri string) (ConfigWriter, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("malformed uri: %w", err)
	}
	if wb := LoadBuilder(u.Scheme); wb != nil {
		return wb(u)
	}
	return nil, fmt.Errorf("unknown scheme: %q", u.Scheme)
}
