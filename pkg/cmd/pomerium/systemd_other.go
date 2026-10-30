//go:build !linux

package pomerium

import "github.com/pomerium/pomerium/pkg/health/v2/sink"

func systemdOptions() (sink.SystemdOptions, bool) {
	return sink.SystemdOptions{}, false
}
