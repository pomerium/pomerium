package sink

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

const (
	sdNotifyReady    = "READY=1"
	sdNotifyStopping = "STOPPING=1"
	sdNotifyWatchdog = "WATCHDOG=1"

	sdNotifyStatusMaxLen = 80
)

type SystemdOptions struct {
	Addr             string
	WatchdogInterval time.Duration
}

// Systemd writes nothing to the socket while it is disabled. When it is enabled
// again, it reports the latest snapshot. READY=1 is sent at most once over the
// life of the sink.
type Systemd struct {
	SystemdOptions
	progress pollProgress
	conn     io.WriteCloser
	log      zerolog.Logger

	enabled atomic.Bool

	latest        *latestSnapshot
	notifiedReady bool
	sentReasons   map[string]string

	stopping sync.Once
}

var _ healthv2.HealthSink = (*Systemd)(nil)

func NewSystemd(progress pollProgress, opts SystemdOptions) (*Systemd, error) {
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: opts.Addr, Net: "unixgram"})
	if err != nil {
		return nil, err
	}
	return newSystemd(conn, progress, opts), nil
}

func newSystemd(conn io.WriteCloser, progress pollProgress, opts SystemdOptions) *Systemd {
	s := &Systemd{
		SystemdOptions: opts,
		progress:       progress,
		conn:           conn,
		log:            log.With().Str("component", "sd_notify").Logger(),
		latest:         newLatestSnapshot(),
		sentReasons:    map[string]string{},
	}
	s.enabled.Store(true)
	return s
}

func (s *Systemd) SetEnabled(enabled bool) {
	if wasEnabled := s.enabled.Swap(enabled); enabled && !wasEnabled {
		s.latest.resignal()
	}
}

// Run sends WATCHDOG=1 while the last poll is within WatchdogInterval/2.
func (s *Systemd) Run() {
	go s.processSnapshots()
	if s.WatchdogInterval > 0 {
		go s.runWatchdog()
	}
}

// Notify sends READY=1 at most once, when the snapshot is first initialized.
func (s *Systemd) Notify(snap healthv2.Snapshot) { s.latest.store(snap) }

// Shutdown sends STOPPING=1 at most once and returns after it has been written
// or its retry has given up. Safe to call concurrently with Notify.
func (s *Systemd) Shutdown(ctx context.Context) {
	s.stopping.Do(func() {
		if !s.enabled.Load() {
			return
		}
		cause := context.Cause(ctx)
		ctx = log.Ctx(ctx).With().Str("component", "sd_notify").Logger().WithContext(context.WithoutCancel(ctx))
		log.Ctx(ctx).Info().Err(cause).Msg("shutting down")
		s.sendWithRetry(ctx, sdNotifyStopping)
	})
}

func (s *Systemd) processSnapshots() {
	for range s.latest.signal {
		s.report(s.latest.load())
	}
}

func (s *Systemd) report(snap healthv2.Snapshot) {
	if !s.enabled.Load() {
		return
	}
	s.reportReasons(snap)
	if !s.notifiedReady && snap.Initialized() {
		s.notifiedReady = true
		go s.sendWithRetry(s.log.WithContext(context.Background()), sdNotifyReady)
	}
}

func (s *Systemd) reportReasons(snap healthv2.Snapshot) {
	reasons := map[string]string{}
	for _, c := range snap.Checkers {
		reason, ok := reportableReason(c)
		if !ok {
			continue
		}
		reasons[c.Key()] = reason
		if s.sentReasons[c.Key()] != reason {
			s.send(truncate(fmt.Sprintf("STATUS=%s: %s", c.Key(), reason), sdNotifyStatusMaxLen))
		}
	}
	s.sentReasons = reasons
}

func reportableReason(c healthv2.CheckerStatus) (string, bool) {
	reason, failed := c.Reason()
	return reason, failed && reason != ""
}

func (s *Systemd) runWatchdog() {
	t := time.NewTicker(s.WatchdogInterval / 2)
	defer t.Stop()
	for range t.C {
		if !s.enabled.Load() {
			continue
		}
		if s.shouldHeartbeat() {
			s.send(sdNotifyWatchdog)
		} else {
			s.log.Warn().Time("last-poll", s.progress.LastPoll()).Msg("health manager stalled, skipping watchdog heartbeat")
		}
	}
}

func (s *Systemd) shouldHeartbeat() bool {
	return time.Since(s.progress.LastPoll()) <= s.WatchdogInterval/2
}

func (s *Systemd) send(msg string) {
	if _, err := s.conn.Write([]byte(msg)); err != nil {
		s.log.Error().Err(err).Str("msg", msg).Msg("failed to notify systemd")
	}
}

func (s *Systemd) sendWithRetry(ctx context.Context, msg string) {
	retrier := backoff.WithContext(backoff.NewExponentialBackOff(
		backoff.WithInitialInterval(time.Second),
		backoff.WithMaxInterval(5*time.Second),
	), ctx)
	err := backoff.Retry(func() error {
		_, err := s.conn.Write([]byte(msg))
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("msg", msg).Msg("failed to notify systemd")
		}
		return err
	}, retrier)
	if err == nil {
		log.Ctx(ctx).Info().Str("msg", msg).Msg("notified systemd")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
