package idpsession

import (
	"context"
	"time"
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
