package tripper // import "github.com/pomerium/pomerium/internal/tripper"

import "net/http"

// Constructor is a type alias for func(http.RoundTripper) http.RoundTripper
type Constructor func(http.RoundTripper) http.RoundTripper

// Chain acts as a list of http.RoundTripper constructors.
// Chain is effectively immutable:
// once created, it will always hold
// the same set of constructors in the same order.
type Chain struct {
	constructors []Constructor
}

// NewChain creates a new chain,
// memorizing the given list of tripper constructors.
// New serves no other function,
// constructors are only called upon a call to Then().
func NewChain(constructors ...Constructor) Chain {
	return Chain{append([]Constructor(nil), constructors...)}
}

// Then chains the trippers and returns the final http.RoundTripper.
//     NewChain(m1, m2, m3).Then(h)
// is equivalent to:
//     m1(m2(m3(h)))
// When the request comes in, it will be passed to m1, then m2, then m3
// and finally, the given roundtripper
// (assuming every tripper calls the following one).
//
// A chain can be safely reused by calling Then() several times.
//     stdStack := tripper.NewChain(ratelimitTripper, csrfTripper)
//     tracePipe = stdStack.Then(traceTripper)
//     authPipe = stdStack.Then(authTripper)
// Note that constructors are called on every call to Then()
// and thus several instances of the same tripper will be created
// when a chain is reused in this way.
// For proper tripper implementations, this should cause no problems.
//
// Then() treats nil as http.DefaultTransport.
func (c Chain) Then(h http.RoundTripper) http.RoundTripper {
	if h == nil {
		h = http.DefaultTransport
	}

	for i := range c.constructors {
		h = c.constructors[len(c.constructors)-1-i](h)
	}

	return h
}

// Append extends a chain, adding the specified constructors
// as the last ones in the request flow.
//
// Append returns a new chain, leaving the original one untouched.
//
//     stdChain := middleware.NewChain(m1, m2)
//     extChain := stdChain.Append(m3, m4)
//     // requests in stdChain go m1 -> m2
//     // requests in extChain go m1 -> m2 -> m3 -> m4
func (c Chain) Append(constructors ...Constructor) Chain {
	newCons := make([]Constructor, 0, len(c.constructors)+len(constructors))
	newCons = append(newCons, c.constructors...)
	newCons = append(newCons, constructors...)

	return Chain{newCons}
}
