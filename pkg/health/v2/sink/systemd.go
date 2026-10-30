package sink

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
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

// READY=1 and STOPPING=1 are each sent at most once. Close does not return
// until a due STOPPING=1 has been written. WATCHDOG=1 is sent while the
// manager finished a poll within the last WatchdogInterval/2, and after the
// manager starts terminating.
type Systemd struct {
	SystemdOptions
	progress pollProgress
	conn     io.WriteCloser
	log      zerolog.Logger

	latest           *latestSnapshot
	notifiedReady    bool
	notifiedStopping bool
	sentErrs         map[check.CheckName]string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
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
		sentErrs:       map[check.CheckName]string{},
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.wg.Go(s.processSnapshots)
	if opts.WatchdogInterval > 0 {
		s.wg.Go(s.runWatchdog)
	}
	return s
}

func (s *Systemd) Notify(snap healthv2.Snapshot) { s.latest.store(snap) }

func (s *Systemd) Close() {
	s.cancel()
	s.wg.Wait()
	_ = s.conn.Close()
}

func (s *Systemd) processSnapshots() {
	for {
		select {
		case <-s.latest.signal:
			s.report(s.latest.load())
		case <-s.ctx.Done():
			s.reportPending()
			return
		}
	}
}

func (s *Systemd) reportPending() {
	select {
	case <-s.latest.signal:
		s.report(s.latest.load())
	default:
	}
}

func (s *Systemd) report(snap healthv2.Snapshot) {
	s.reportErrors(snap)
	if !s.notifiedReady && snap.AllRunning() {
		s.notifiedReady = true
		s.wg.Go(func() { s.sendWithRetry(sdNotifyReady) })
	}
	if !s.notifiedStopping && snap.AnyTerminating() {
		s.notifiedStopping = true
		s.wg.Go(func() { s.sendWithRetry(sdNotifyStopping) })
	}
}

func (s *Systemd) reportErrors(snap healthv2.Snapshot) {
	errs := map[check.CheckName]string{}
	for _, c := range snap.Checkers {
		for _, r := range c.Results {
			if r.Err == nil {
				continue
			}
			errs[r.Name] = r.Err.Error()
			if s.sentErrs[r.Name] != errs[r.Name] {
				s.send(truncate(fmt.Sprintf("STATUS=Error in %s: %s", r.Name, errs[r.Name]), sdNotifyStatusMaxLen))
			}
		}
	}
	s.sentErrs = errs
}

func (s *Systemd) runWatchdog() {
	t := time.NewTicker(s.WatchdogInterval / 2)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if s.shouldHeartbeat() {
				s.send(sdNotifyWatchdog)
			} else {
				s.log.Warn().Time("last-poll", s.progress.LastPoll()).Msg("health manager stalled, skipping watchdog heartbeat")
			}
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Systemd) shouldHeartbeat() bool {
	return s.latest.load().Terminating || time.Since(s.progress.LastPoll()) <= s.WatchdogInterval/2
}

func (s *Systemd) send(msg string) {
	if _, err := s.conn.Write([]byte(msg)); err != nil {
		s.log.Error().Err(err).Str("msg", msg).Msg("failed to notify systemd")
	}
}

func (s *Systemd) sendWithRetry(msg string) {
	retrier := backoff.WithContext(backoff.NewExponentialBackOff(
		backoff.WithInitialInterval(time.Second),
		backoff.WithMaxInterval(5*time.Second),
	), s.ctx)
	err := backoff.Retry(func() error {
		_, err := s.conn.Write([]byte(msg))
		if err != nil {
			s.log.Error().Err(err).Str("msg", msg).Msg("failed to notify systemd")
		}
		return err
	}, retrier)
	if err == nil {
		s.log.Info().Str("msg", msg).Msg("notified systemd")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
