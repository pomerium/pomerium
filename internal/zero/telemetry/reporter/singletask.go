package reporter

import (
	"context"
	"errors"
	"sync"
)

type singleTask struct {
	lock   sync.Mutex
	cancel context.CancelCauseFunc
}

var ErrAnotherExecutionRequested = errors.New("another execution requested")

func (s *singleTask) Run(ctx context.Context, f func(context.Context)) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.cancel != nil {
		s.cancel(ErrAnotherExecutionRequested)
	}

	ctx, cancel := context.WithCancelCause(ctx)
	s.cancel = cancel
	go f(ctx)
}
