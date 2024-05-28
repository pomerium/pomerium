//go:build !linux

package envoy

import (
	"context"
	"errors"

	"github.com/pomerium/pomerium/config"
)

func NewSharedResourceMonitor(ctx context.Context, src config.Source, tempDir string) (ResourceMonitor, error) {
	return nil, errors.New("unsupported platform")
}
