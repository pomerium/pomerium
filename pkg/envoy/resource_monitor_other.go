//go:build !linux

package envoy

import (
	"context"
	"errors"

	"github.com/pomerium/pomerium/config"
)

func NewSharedResourceMonitor(_ context.Context, _ config.Source, _ string) (ResourceMonitor, error) {
	return nil, errors.New("unsupported platform")
}
