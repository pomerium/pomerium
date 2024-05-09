//go:build !linux

package envoy

import "errors"

func NewSharedResourceMonitor(tempDir string) (ResourceMonitor, error) {
	return nil, errors.New("unsupported platform")
}
