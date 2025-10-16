package pending

import "sync"

type pendingValue[T any] struct {
	f          func() T
	set        bool
	version    int
	cond       *sync.Cond
	updateCond *sync.Cond
	cleanup    *sync.Once
	done       chan struct{}
}

func NewPending[T any]() *pendingValue[T] {
	return &pendingValue[T]{
		f:       nil,
		set:     false,
		cond:    sync.NewCond(&sync.Mutex{}),
		cleanup: &sync.Once{},
		done:    make(chan struct{}, 1),
		version: 0,
	}
}
func (p *pendingValue[T]) get() (val T, version int) {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()
	for !p.set {
		p.cond.Wait()
	}
	v := p.f()
	return v, p.version
}

func (p *pendingValue[T]) ResolveFunc(fOnce func() T) {
	p.cond.L.Lock()
	p.f = sync.OnceValue(func() T {
		p.version++
		return fOnce()
	})
	p.set = true
	p.cond.L.Unlock()
	p.cond.Broadcast()
}

func (p *pendingValue[T]) Resolve(value T) {
	p.ResolveFunc(func() T { return value })
}

// Get returns a single use channel that waits until the underlying value
// is set.
// If Get() is called concurrently between sequences of Resolve,
// it is not guaranteed to have the latest value.
// The returned channel is closed when the value itself is closed
func (p *pendingValue[T]) Get() <-chan T {
	ret := make(chan T, 1)
	go func() {
		t, _ := p.get()
		ret <- t
	}()
	go func() {
		<-p.done
		close(ret)
	}()
	return ret
}

// Watch blocks until a value is set, then listens to all updates done to the value
// If called after the first Resolve, then it returns the most recent value and subsequent
// updates as they happen
// The returned channel is closed when the value itself is closed
func (p *pendingValue[T]) Watch() <-chan T {
	ret := make(chan T, 16)
	curVersion := p.version - 1
	go func() {
		for {
			select {
			case <-p.done:
				close(ret)
			default:
				v, version := p.get()
				if version != curVersion {
					ret <- v
					curVersion = p.version
				}
			}
		}
	}()
	return ret
}

func (p *pendingValue[T]) Close() {
	p.cleanup.Do(
		func() {
			close(p.done)
		},
	)
}
