package manager

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

type updateUserInfoScheduler struct {
	baseCtx                context.Context
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
		baseCtx:                ctx,
		updateUserInfoInterval: updateUserInfoInterval,
		updateUserInfo:         updateUserInfo,
		userID:                 userID,
		reset:                  make(chan struct{}, 1),
	}
	ctx, uuis.cancel = context.WithCancel(context.WithoutCancel(uuis.baseCtx))
	go uuis.run(ctx)
	return uuis
}

func (uuis *updateUserInfoScheduler) Reset() {
	// trigger a reset by sending to the reset channel, which is buffered,
	// so if we can't proceed there's already a pending reset and no need
	// to wait
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
			uuis.updateUserInfo(uuis.baseCtx, uuis.userID)
		}
	}
}

type refreshSessionScheduler struct {
	baseCtx                       context.Context
	now                           func() time.Time
	sessionRefreshGracePeriod     time.Duration
	sessionRefreshCoolOffDuration time.Duration
	refreshSession                func(ctx context.Context, sesionID string)
	sessionID                     string
	refreshAtIDTokenExpiration    RefreshSessionAtIDTokenExpiration

	lastRefresh atomic.Pointer[time.Time]
	next        chan time.Time
	cancel      context.CancelFunc
}

func newRefreshSessionScheduler(
	ctx context.Context,
	now func() time.Time,
	sessionRefreshGracePeriod time.Duration,
	sessionRefreshCoolOffDuration time.Duration,
	refreshAtIDTokenExpiration RefreshSessionAtIDTokenExpiration,
	refreshSession func(ctx context.Context, sesionID string),
	sessionID string,
) *refreshSessionScheduler {
	rss := &refreshSessionScheduler{
		baseCtx:                       ctx,
		now:                           now,
		sessionRefreshGracePeriod:     sessionRefreshGracePeriod,
		sessionRefreshCoolOffDuration: sessionRefreshCoolOffDuration,
		refreshAtIDTokenExpiration:    refreshAtIDTokenExpiration,
		refreshSession:                refreshSession,
		sessionID:                     sessionID,
		next:                          make(chan time.Time, 1),
	}
	tm := now()
	rss.lastRefresh.Store(&tm)
	ctx, rss.cancel = context.WithCancel(context.WithoutCancel(rss.baseCtx))
	go rss.run(ctx)
	return rss
}

func (rss *refreshSessionScheduler) Update(s *session.Session) {
	due := nextSessionRefresh(
		s,
		*rss.lastRefresh.Load(),
		rss.sessionRefreshGracePeriod,
		rss.sessionRefreshCoolOffDuration,
		rss.refreshAtIDTokenExpiration,
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
	// ensure we clean up any orphaned timers
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	// wait for the first update
	select {
	case <-ctx.Done():
		return
	case due := <-rss.next:
		delay := max(time.Until(due), 0)
		timer = time.NewTimer(delay)
	}

	// wait for updates or for the timer to trigger
	for {
		select {
		case <-ctx.Done():
			return
		case due := <-rss.next:
			delay := max(time.Until(due), 0)
			// stop the existing timer and start a new one
			timer.Stop()
			timer = time.NewTimer(delay)
		case <-timer.C:
			tm := rss.now()
			rss.lastRefresh.Store(&tm)
			rss.refreshSession(rss.baseCtx, rss.sessionID)
		}
	}
}
