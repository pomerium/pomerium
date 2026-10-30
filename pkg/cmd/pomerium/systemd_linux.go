//go:build linux

package pomerium

import (
	"os"
	"strconv"
	"time"

	"github.com/pomerium/pomerium/pkg/health/v2/sink"
)

// systemdOptions reports false when NOTIFY_SOCKET is unset.
// https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html#Notes
func systemdOptions() (sink.SystemdOptions, bool) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return sink.SystemdOptions{}, false
	}
	return sink.SystemdOptions{Addr: addr, WatchdogInterval: watchdogInterval()}, true
}

// watchdogInterval returns 0 when the watchdog is disabled.
// https://www.freedesktop.org/software/systemd/man/latest/sd_watchdog_enabled.html#Environment
// TODO : should default to something sane when we can't parse.
func watchdogInterval() time.Duration {
	usec, err := strconv.Atoi(os.Getenv("WATCHDOG_USEC"))
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(os.Getenv("WATCHDOG_PID"))
	if err != nil || pid != os.Getpid() {
		return 0
	}
	return time.Duration(usec) * time.Microsecond
}
