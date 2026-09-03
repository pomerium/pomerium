package idpsession

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
)

type refreshIDPSessionScheduler struct {
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

func (rss *refreshIDPSessionScheduler) Update(s *idpsession.IDPSession) {
	due := nextIDPSessionRefresh(
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

func (rss *refreshIDPSessionScheduler) Stop() {
	rss.cancel()
}

func (rss *refreshIDPSessionScheduler) run(ctx context.Context) {
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

// RefreshSessionAtIDTokenExpiration indicates whether a session refresh should be
// scheduled at the expiration time of the ID token.
type RefreshSessionAtIDTokenExpiration bool

func nextIDPSessionRefresh(
	s *idpsession.IDPSession,
	lastRefresh time.Time,
	gracePeriod time.Duration,
	coolOffDuration time.Duration,
	refreshAtIDTokenExpiration RefreshSessionAtIDTokenExpiration,
) time.Time {
	var tm time.Time

	if s.GetOauthToken().GetExpiresAt() != nil {
		expiry := s.GetOauthToken().GetExpiresAt().AsTime()
		if s.GetOauthToken().GetExpiresAt().IsValid() && !expiry.IsZero() {
			expiry = expiry.Add(-gracePeriod)
			if tm.IsZero() || expiry.Before(tm) {
				tm = expiry
			}
		}
	}

	if refreshAtIDTokenExpiration && s.GetIdToken().GetExpiresAt() != nil {
		expiry := s.GetIdToken().GetExpiresAt().AsTime()
		if s.GetIdToken().GetExpiresAt().IsValid() && !expiry.IsZero() {
			expiry = expiry.Add(-gracePeriod)
			if tm.IsZero() || expiry.Before(tm) {
				tm = expiry
			}
		}
	}

	// !!! idpsession doesn't have a max expiry ...

	// if s.GetExpiresAt() != nil {
	// 	expiry := s.GetExpiresAt().AsTime()
	// 	if s.GetExpiresAt().IsValid() && !expiry.IsZero() {
	// 		if tm.IsZero() || expiry.Before(tm) {
	// 			tm = expiry
	// 		}
	// 	}
	// }

	// don't refresh any quicker than the cool-off duration
	v := lastRefresh.Add(coolOffDuration)
	if tm.Before(v) {
		tm = v
	}

	return tm
}

func newRefreshSessionScheduler(
	ctx context.Context,
	now func() time.Time,
	sessionRefreshGracePeriod time.Duration,
	sessionRefreshCoolOffDuration time.Duration,
	refreshAtIDTokenExpiration RefreshSessionAtIDTokenExpiration,
	refreshSession func(ctx context.Context, idpsessionID string),
	idpSessionID string,
) *refreshIDPSessionScheduler {
	rss := &refreshIDPSessionScheduler{
		baseCtx:                       ctx,
		now:                           now,
		sessionRefreshGracePeriod:     sessionRefreshGracePeriod,
		sessionRefreshCoolOffDuration: sessionRefreshCoolOffDuration,
		refreshAtIDTokenExpiration:    refreshAtIDTokenExpiration,
		refreshSession:                refreshSession,
		sessionID:                     idpSessionID,
		next:                          make(chan time.Time, 1),
	}
	tm := now()
	rss.lastRefresh.Store(&tm)
	ctx, rss.cancel = context.WithCancel(context.WithoutCancel(rss.baseCtx))
	go rss.run(ctx)
	return rss
}
