package manager

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

type updateUserInfoScheduler struct {
	updateUserInfoInterval time.Duration
	updateUserInfo         func(ctx context.Context, userID string)
	userID                 string

	reset  chan struct{}
	cancel context.CancelFunc
}

func newUpdateUserInfoScheduler(
	ctx context.Context,
	updateUserInfoInterval time.Duration,
	updateUserInfo func(ctx context.Context, userID string),
	userID string,
) *updateUserInfoScheduler {
	uuis := &updateUserInfoScheduler{
		updateUserInfoInterval: updateUserInfoInterval,
		updateUserInfo:         updateUserInfo,
		userID:                 userID,
		reset:                  make(chan struct{}, 1),
	}
	ctx = context.WithoutCancel(ctx)
	ctx, uuis.cancel = context.WithCancel(ctx)
	go uuis.run(ctx)
	return uuis
}

func (uuis *updateUserInfoScheduler) Reset() {
	select {
	case uuis.reset <- struct{}{}:
	default:
	}
}

func (uuis *updateUserInfoScheduler) Stop() {
	uuis.cancel()
}

func (uuis *updateUserInfoScheduler) run(ctx context.Context) {
	ticker := time.NewTicker(uuis.updateUserInfoInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-uuis.reset:
			ticker.Reset(uuis.updateUserInfoInterval)
		case <-ticker.C:
			uuis.updateUserInfo(ctx, uuis.userID)
		}
	}
}

type refreshSessionScheduler struct {
	mgr         *Manager
	sessionID   string
	lastRefresh atomic.Pointer[time.Time]
	next        chan time.Time
	cancel      context.CancelFunc
}

func newRefreshSessionScheduler(
	ctx context.Context,
	mgr *Manager,
	sessionID string,
) *refreshSessionScheduler {
	rss := &refreshSessionScheduler{
		mgr:       mgr,
		sessionID: sessionID,
		next:      make(chan time.Time, 1),
	}
	now := rss.mgr.cfg.Load().now()
	rss.lastRefresh.Store(&now)
	ctx = context.WithoutCancel(ctx)
	ctx, rss.cancel = context.WithCancel(ctx)
	go rss.run(ctx)
	return rss
}

func (rss *refreshSessionScheduler) Update(s *session.Session) {
	due := nextSessionRefresh(
		s,
		*rss.lastRefresh.Load(),
		rss.mgr.cfg.Load().sessionRefreshGracePeriod,
		rss.mgr.cfg.Load().sessionRefreshCoolOffDuration,
	)
	for {
		select {
		case <-rss.next:
		default:
		}
		select {
		case rss.next <- due:
			return
		default:
		}
	}
}

func (rss *refreshSessionScheduler) Stop() {
	rss.cancel()
}

func (rss *refreshSessionScheduler) run(ctx context.Context) {
	var timer *time.Timer

	// wait for the first update
	select {
	case <-ctx.Done():
		return
	case due := <-rss.next:
		delay := max(time.Until(due), 0)
		timer = time.NewTimer(delay)
		defer timer.Stop()
	}

	// wait for updates or for the timer to trigger
	for {
		select {
		case <-ctx.Done():
			return
		case due := <-rss.next:
			delay := max(time.Until(due), 0)
			// stop the current timer and reset it
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(delay)
		case <-timer.C:
			now := rss.mgr.cfg.Load().now()
			rss.lastRefresh.Store(&now)
			rss.mgr.refreshSession(ctx, rss.sessionID)
		}
	}
}
