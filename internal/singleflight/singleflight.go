// Original Copyright 2013 The Go Authors. All rights reserved.
//
// Modified by BuzzFeed to return duplicate counts.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package singleflight provides a duplicate function call suppression mechanism.
package singleflight // import "github.com/pomerium/pomerium/internal/singleflight"

import "sync"

// call is an in-flight or completed singleflight.Do call
type call struct {
	wg sync.WaitGroup

	// These fields are written once before the WaitGroup is done
	// and are only read after the WaitGroup is done.
	val interface{}
	err error

	// These fields are read and written with the singleflight
	// mutex held before the WaitGroup is done, and are read but
	// not written after the WaitGroup is done.
	dups int
}

// Group represents a class of work and forms a namespace in
// which units of work can be executed with duplicate suppression.
type Group struct {
	mu sync.Mutex       // protects m
	m  map[string]*call // lazily initialized
}

// Result holds the results of Do, so they can be passed
// on a channel.
type Result struct {
	Val   interface{}
	Err   error
	Count bool
}

// Do executes and returns the results of the given function, making
// sure that only one execution is in-flight for a given key at a
// time. If a duplicate comes in, the duplicate caller waits for the
// original to complete and receives the same results.
// The return value of Count indicates how many tiems v was given to multiple callers.
// Count will be zero for requests are shared and only be non-zero for the originating request.
func (g *Group) Do(key string, fn func() (interface{}, error)) (v interface{}, count int, err error) {
	g.mu.Lock()

	if g.m == nil {
		g.m = make(map[string]*call)
	}
	if c, ok := g.m[key]; ok {
		c.dups++
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, 0, c.err
	}
	c := new(call)
	c.wg.Add(1)
	g.m[key] = c

	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	return c.val, c.dups, c.err
}
