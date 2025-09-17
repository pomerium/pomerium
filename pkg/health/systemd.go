package health

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
)

const (
	// sdNotifyReady tells the service manager that service startup is finished
	// or the service finished loading its configuration.
	sdNotifyReady = "READY=1"

	// SdNotifyStopping tells the service manager that the service is beginning
	// its shutdown.
	sdNotifyStopping = "STOPPING=1"

	// SdNotifyWatchdog tells the service manager to update the watchdog
	// timestamp for the service.
	sdNotifyWatchdog = "WATCHDOG=1"
)

var SdNotifyStatus = func(st string) string {
	return "STATUS=" + st
}

// SystemdProvider provides health reports to sd_notify, which is the protocol consumed by
// systemd & systemctl.
// Reference : https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html#Description
type SystemdProvider struct {
	ctx context.Context
	ca  context.CancelFunc

	log zerolog.Logger

	conn      *net.UnixConn
	watchConf SystemdWatchdogConf

	expectedChecks map[Check]struct{}
	tr             Tracker

	notifiedReady    *atomic.Bool
	notifiedStopping *atomic.Bool
	done             chan struct{}
}

type SystemdWatchdogConf struct {
	Enabled  bool
	Interval time.Duration
}

var _ Provider = (*SystemdProvider)(nil)

func NewSystemDProvider(
	parentCtx context.Context,
	tr Tracker,
	addr string,
	watchConf SystemdWatchdogConf,
	opts ...CheckOption,
) (*SystemdProvider, error) {
	options := CheckOptions{}
	options.Apply(opts...)

	sockAddr := &net.UnixAddr{
		Name: addr,
		Net:  "unixgram",
	}
	conn, err := net.DialUnix(sockAddr.Net, nil, sockAddr)
	if err != nil {
		return nil, err
	}
	ready, stopping := &atomic.Bool{}, &atomic.Bool{}
	ready.Store(false)
	stopping.Store(false)

	ctx := context.WithoutCancel(parentCtx)
	ctxca, ca := context.WithCancel(ctx)
	logger := log.With().Str("component", "sd_notify").Bool("watchdog", watchConf.Enabled).Logger()

	s := &SystemdProvider{
		log:              logger,
		ctx:              ctxca,
		ca:               ca,
		conn:             conn,
		tr:               tr,
		watchConf:        watchConf,
		expectedChecks:   options.expected,
		notifiedReady:    ready,
		notifiedStopping: stopping,
		done:             make(chan struct{}, 1),
	}

	return s, nil
}

func (s *SystemdProvider) Start() {
	if s.watchConf.Enabled {
		s.log.Info().Msg("starting watchdog")
		go s.runWatchdog()
	}
}

func (s *SystemdProvider) Shutdown() {
	s.log.Info().Msg("shutting down")
	defer s.ca()
	close(s.done)
}

func (s *SystemdProvider) runWatchdog() {
	t := time.NewTicker(s.watchConf.Interval / 2)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.log.Debug().Msg("pushing heartbeat to watchdog...")
			_, err := s.conn.Write([]byte(sdNotifyWatchdog))
			if err != nil {
				s.log.Error().Err(err).Msg("failed to hearbeat to watchdog")
			}
		case <-s.done:
			return
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *SystemdProvider) isStarted() bool {
	recs := s.tr.GetRecords()
	for check := range s.expectedChecks {
		rec, ok := recs[check]
		if !ok {
			return false
		}
		if rec.status != StatusRunning {
			return false
		}
	}
	return true
}

func (s *SystemdProvider) ReportStatus(Check, Status, ...Attr) {
	s.reportStarted()
	s.reportStopping()
}

func (s *SystemdProvider) reportStarted() {
	if s.notifiedReady.Load() {
		return
	}
	if !s.isStarted() {
		return
	}
	s.notifiedReady.Store(true)
	go func() {
		retrier := backoff.WithContext(backoff.NewExponentialBackOff(
			backoff.WithInitialInterval(time.Second),
			backoff.WithMaxInterval(time.Second*5),
		), s.ctx)

		_ = backoff.Retry(func() error {
			_, err := s.conn.Write([]byte(sdNotifyReady))
			if err != nil {
				s.log.Error().Msg("failed to report ready")
			}
			return err
		}, retrier)
		s.log.Info().Msg("reported ready")
	}()
}

func (s *SystemdProvider) isStopping() bool {
	recs := s.tr.GetRecords()
	for _, rec := range recs {
		if rec.status == StatusTerminating {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func (s *SystemdProvider) reportStopping() {
	if s.notifiedStopping.Load() {
		return
	}
	if !s.isStopping() {
		return
	}
	s.notifiedStopping.Store(true)
	go func() {
		retrier := backoff.WithContext(backoff.NewExponentialBackOff(
			backoff.WithInitialInterval(time.Second),
			backoff.WithMaxInterval(time.Second*5),
		), s.ctx)

		_ = backoff.Retry(func() error {
			_, err := s.conn.Write([]byte(sdNotifyStopping))
			if err != nil {
				s.log.Error().Msg("failed to report stopping")
			}
			return err
		}, retrier)
		s.log.Info().Msg("reported stopping")
	}()
}

func (s *SystemdProvider) ReportError(check Check, err error, _ ...Attr) {
	// while sd_notify can accept up to 64Kb, 80 characters is readable from
	// the terminal
	stStr := truncate(SdNotifyStatus(fmt.Sprintf("Error in %s: %s", check, err.Error())), 80)
	// this doesn't block
	if _, err := s.conn.Write([]byte(stStr)); err != nil {
		s.log.Error().Msg("failed to report error status")
	}
}
