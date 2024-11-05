package values

import (
	"math/rand/v2"
	"sync"
)

type value[T any] struct {
	f     func() T
	ready bool
	cond  *sync.Cond
}

// A Value is a container for a single value of type T, whose initialization is
// performed the first time Value() is called. Subsequent calls will return the
// same value. The Value() function may block until the value is ready on the
// first call. Values are safe to use concurrently.
type Value[T any] interface {
	Value() T
}

// MutableValue is the read-write counterpart to [Value], created by calling
// [Deferred] for some type T. Calling Resolve() or ResolveFunc() will set
// the value and unblock any waiting calls to Value().
type MutableValue[T any] interface {
	Value[T]
	Resolve(value T)
	ResolveFunc(fOnce func() T)
}

// Deferred creates a new read-write [MutableValue] for some type T,
// representing a value whose initialization may be deferred to a later time.
// Once the value is available, call [MutableValue.Resolve] or
// [MutableValue.ResolveFunc] to unblock any waiting calls to Value().
func Deferred[T any]() MutableValue[T] {
	return &value[T]{
		cond: sync.NewCond(&sync.Mutex{}),
	}
}

// Const creates a read-only [Value] which will become available immediately
// upon calling Value() for the first time; it will never block.
func Const[T any](t T) Value[T] {
	return &value[T]{
		f:     func() T { return t },
		ready: true,
		cond:  sync.NewCond(&sync.Mutex{}),
	}
}

func (p *value[T]) Value() T {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()
	for !p.ready {
		p.cond.Wait()
	}
	return p.f()
}

func (p *value[T]) ResolveFunc(fOnce func() T) {
	p.cond.L.Lock()
	p.f = sync.OnceValue(fOnce)
	p.ready = true
	p.cond.L.Unlock()
	p.cond.Broadcast()
}

func (p *value[T]) Resolve(value T) {
	p.ResolveFunc(func() T { return value })
}

// Bind creates a new [MutableValue] whose ultimate value depends on the result
// of another [Value] that may not yet be available. When Value() is called on
// the result, it will cascade and trigger the full chain of initialization
// functions necessary to produce the final value.
//
// Care should be taken when using this function, as improper use can lead to
// deadlocks and cause values to never become available.
func Bind[T any, U any](dt Value[T], callback func(value T) U) Value[U] {
	du := Deferred[U]()
	du.ResolveFunc(func() U {
		return callback(dt.Value())
	})
	return du
}

// Bind2 is like [Bind], but can accept two input values. The result will only
// become available once all input values become available.
//
// This function blocks to wait for each input value in sequence, but in a
// random order. Do not rely on the order of evaluation of the input values.
func Bind2[T any, U any, V any](dt Value[T], du Value[U], callback func(value1 T, value2 U) V) Value[V] {
	dv := Deferred[V]()
	dv.ResolveFunc(func() V {
		if rand.IntN(2) == 0 { //nolint:gosec
			return callback(dt.Value(), du.Value())
		}
		u := du.Value()
		t := dt.Value()
		return callback(t, u)
	})
	return dv
}

// List is a container for a slice of [Value] of type T, and is also a [Value]
// itself, for convenience. The Value() function will return a []T containing
// all resolved values for each element in the slice.
//
// A List's Value() function blocks to wait for each element in the slice in
// sequence, but in a random order. Do not rely on the order of evaluation of
// the slice elements.
type List[T any] []Value[T]

func (s List[T]) Value() []T {
	values := make([]T, len(s))
	for _, i := range rand.Perm(len(values)) {
		values[i] = s[i].Value()
	}
	return values
}
