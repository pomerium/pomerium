package portforward_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

func TestPermissionSet_AddRemove(t *testing.T) {
	for _, tc := range []struct {
		name  string
		perm1 *portforward.Permission
		perm2 *portforward.Permission
	}{
		{
			name: "Static",
			perm1: &portforward.Permission{
				Context:       t.Context(),
				HostMatcher:   portforward.GlobHostMatcher("one"),
				RequestedPort: 1234,
			},
			perm2: &portforward.Permission{
				Context:       t.Context(),
				HostMatcher:   portforward.GlobHostMatcher("two"),
				RequestedPort: 2345,
			},
		},
		{
			name: "Dynamic",
			perm1: &portforward.Permission{
				Context:       t.Context(),
				HostMatcher:   portforward.GlobHostMatcher("one"),
				RequestedPort: 0,
				VirtualPort:   1234,
			},
			perm2: &portforward.Permission{
				Context:       t.Context(),
				HostMatcher:   portforward.GlobHostMatcher("two"),
				RequestedPort: 0,
				VirtualPort:   2345,
			},
		},
		{
			name: "StaticAndDynamic",
			perm1: &portforward.Permission{
				Context:       t.Context(),
				HostMatcher:   portforward.GlobHostMatcher("one"),
				RequestedPort: 1234,
			},
			perm2: &portforward.Permission{
				Context:       t.Context(),
				HostMatcher:   portforward.GlobHostMatcher("two"),
				RequestedPort: 0,
				VirtualPort:   2345,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps := portforward.PermissionSet{}
			assert.Equal(t, 0, ps.EntryCount())
			ps.Add(tc.perm1)
			assert.Equal(t, 1, ps.EntryCount())
			ps.Add(tc.perm2)
			assert.Equal(t, 2, ps.EntryCount())

			host1, port1 := tc.perm1.HostMatcher.InputPattern(), tc.perm1.ServerPort().Value
			host2, port2 := tc.perm2.HostMatcher.InputPattern(), tc.perm2.ServerPort().Value

			{
				p, ok := ps.Find(host1, port1)
				assert.True(t, ok)
				assert.Same(t, tc.perm1, p)
			}
			{
				p, ok := ps.Find(host2, port2)
				assert.True(t, ok)
				assert.Same(t, tc.perm2, p)
			}
			{
				p, ok := ps.Find(tc.perm1.HostMatcher.InputPattern(), tc.perm2.ServerPort().Value)
				assert.False(t, ok)
				assert.Nil(t, p)
			}
			{
				p, ok := ps.Find("nonexistent", 9999)
				assert.False(t, ok)
				assert.Nil(t, p)
			}

			testError := errors.New("test error")
			ps.Remove(tc.perm1, testError)
			{
				p, ok := ps.Find(host1, port1)
				assert.False(t, ok)
				assert.Nil(t, p)
			}
			assert.Equal(t, testError, context.Cause(tc.perm1.Context))

			ps.Remove(tc.perm2, errors.New("test error")) // should be a no-op
		})
	}
}

func TestPermissionSet_CancelReset(t *testing.T) {
	for _, tc := range []struct {
		name  string
		perm1 *portforward.Permission
		perm2 *portforward.Permission
	}{
		{
			name: "Static",
			perm1: &portforward.Permission{
				Context:       t.Context(),
				HostMatcher:   portforward.GlobHostMatcher("one"),
				RequestedPort: 1234,
			},
			perm2: &portforward.Permission{
				Context:       t.Context(),
				HostMatcher:   portforward.GlobHostMatcher("two"),
				RequestedPort: 2345,
			},
		},
	} {
		t.Run("CancelReset", func(t *testing.T) {
			ps := portforward.PermissionSet{}

			var ca1 context.CancelCauseFunc
			tc.perm1.Context, ca1 = context.WithCancelCause(t.Context())
			ps.Add(tc.perm1)

			var ca2 context.CancelCauseFunc
			tc.perm2.Context, ca2 = context.WithCancelCause(t.Context())
			ps.Add(tc.perm2)

			testError := errors.New("test error")
			ca1(testError)
			assert.Equal(t, testError, context.Cause(tc.perm1.Context))

			host1, port1 := tc.perm1.HostMatcher.InputPattern(), tc.perm1.ServerPort().Value
			host2, port2 := tc.perm2.HostMatcher.InputPattern(), tc.perm2.ServerPort().Value
			{
				p, ok := ps.Find(host1, port1)
				assert.False(t, ok)
				assert.Nil(t, p)
			}

			{
				p, ok := ps.Find(host2, port2)
				assert.True(t, ok)
				assert.Same(t, tc.perm2, p)
			}

			testError2 := errors.New("test error 2")
			ca2(testError2)
			assert.Equal(t, testError2, context.Cause(tc.perm2.Context))

			{
				p, ok := ps.Find(host1, port1)
				assert.False(t, ok)
				assert.Nil(t, p)
			}

			{
				p, ok := ps.Find(host2, port2)
				assert.False(t, ok)
				assert.Nil(t, p)
			}

			ps.ResetCanceled(t.Context(), uint(port1))

			{
				p, ok := ps.Find(host1, port1)
				assert.True(t, ok)
				assert.Same(t, tc.perm1, p)
			}

			{
				p, ok := ps.Find(host2, port2)
				assert.False(t, ok)
				assert.Nil(t, p)
			}

			ps.ResetCanceled(t.Context(), uint(port2))
			{
				p, ok := ps.Find(host1, port1)
				assert.True(t, ok)
				assert.Same(t, tc.perm1, p)
			}

			{
				p, ok := ps.Find(host2, port2)
				assert.True(t, ok)
				assert.Same(t, tc.perm2, p)
			}
		})
	}
}

func TestPermissionSet_CancelResetDynamic(t *testing.T) {
	ps := portforward.PermissionSet{}
	ctx, ca := context.WithCancelCause(t.Context())
	ps.Add(&portforward.Permission{
		Context:       ctx,
		HostMatcher:   portforward.GlobHostMatcher("one"),
		RequestedPort: 0,
		VirtualPort:   1234,
	})
	ca(errors.New("test error"))

	{
		p, ok := ps.Find("one", 1234)
		assert.False(t, ok)
		assert.Nil(t, p)
	}

	// ResetCanceled should be a no-op for dynamic ports
	ps.ResetCanceled(t.Context(), 1234)

	{
		p, ok := ps.Find("one", 1234)
		assert.False(t, ok)
		assert.Nil(t, p)
	}

	assert.Panics(t, func() {
		ps.ResetCanceled(t.Context(), 0)
	})
}

func TestPermissionSet_CancelResetMultiple(t *testing.T) {
	ps := portforward.PermissionSet{}
	ctx, ca := context.WithCancelCause(t.Context())
	perm1 := &portforward.Permission{
		Context:       ctx,
		HostMatcher:   portforward.GlobHostMatcher("one"),
		RequestedPort: 1234,
	}
	perm2 := &portforward.Permission{
		Context:       ctx,
		HostMatcher:   portforward.GlobHostMatcher("two"),
		RequestedPort: 1234,
	}
	perm3 := &portforward.Permission{
		Context:       ctx,
		HostMatcher:   portforward.GlobHostMatcher("three"),
		RequestedPort: 1234,
	}
	ps.Add(perm1)
	ps.Add(perm2)
	ps.Add(perm3)

	for _, host := range []string{"one", "two", "three"} {
		p, ok := ps.Find(host, 1234)
		assert.True(t, ok)
		assert.NotNil(t, p)
	}
	ca(errors.New("test error"))

	for _, host := range []string{"one", "two", "three"} {
		p, ok := ps.Find(host, 1234)
		assert.False(t, ok)
		assert.Nil(t, p)
	}

	ps.ResetCanceled(t.Context(), 1234)

	for _, host := range []string{"one", "two", "three"} {
		p, ok := ps.Find(host, 1234)
		assert.True(t, ok)
		assert.NotNil(t, p)
	}
}

func TestPermissionSet_CancelResetThenRemove(t *testing.T) {
	ps := portforward.PermissionSet{}
	ctx, ca := context.WithCancelCause(t.Context())
	perm1 := &portforward.Permission{
		Context:       ctx,
		HostMatcher:   portforward.GlobHostMatcher("one"),
		RequestedPort: 1234,
	}
	ps.Add(perm1)
	ca(errors.New("test error 1"))

	ctx2, ca2 := context.WithCancelCause(t.Context())
	defer ca2(errors.New("unused"))

	ps.ResetCanceled(ctx2, 1234)

	perm1Ref, _ := ps.Find("one", 1234)
	perm1CtxRef := perm1Ref.Context
	assert.Nil(t, perm1CtxRef.Err())

	errRemove := errors.New("test error 2")
	ps.Remove(perm1, errRemove)

	assert.Equal(t, errRemove, context.Cause(perm1CtxRef))
}

func TestPermissionSet_Match(t *testing.T) {
	static1 := &portforward.Permission{
		Context:       t.Context(),
		HostMatcher:   portforward.GlobHostMatcher("one"),
		RequestedPort: 1234,
	}
	static2 := &portforward.Permission{
		Context:       t.Context(),
		HostMatcher:   portforward.GlobHostMatcher("two"),
		RequestedPort: 1234,
	}
	canceled1 := &portforward.Permission{
		Context: func() context.Context {
			canceled, ca := context.WithCancel(t.Context())
			ca()
			return canceled
		}(),
		HostMatcher:   portforward.GlobHostMatcher("three"),
		RequestedPort: 1234,
	}
	dynamic1 := &portforward.Permission{
		Context:       t.Context(),
		HostMatcher:   portforward.GlobHostMatcher("dynamic1-*"),
		RequestedPort: 0,
		VirtualPort:   10000,
	}
	dynamic2 := &portforward.Permission{
		Context:       t.Context(),
		HostMatcher:   portforward.GlobHostMatcher("*_dynamic2"),
		RequestedPort: 0,
		VirtualPort:   20000,
	}
	type matchParams struct {
		host     string
		port     uint32
		fail     bool
		expected int // index into 'set'
	}
	for _, tc := range []struct {
		name    string
		set     []*portforward.Permission
		matches []matchParams
	}{
		{
			name: "",
			set: []*portforward.Permission{
				0: static1,
				1: static2,
				2: canceled1,
				3: dynamic1,
				4: dynamic2,
			},
			matches: []matchParams{
				{
					host:     "one",
					port:     1234,
					expected: 0,
				},
				{
					host:     "two",
					port:     1234,
					expected: 1,
				},
				{
					host: "three",
					port: 1234,
					fail: true,
				},
				{
					host:     "dynamic1-a",
					port:     10001, // port should not need to match here
					expected: 3,
				},
				{
					host:     "a_dynamic2",
					port:     20001, // port should not need to match here
					expected: 4,
				},
				{
					host:     "dynamic1-b",
					port:     0,
					expected: 3,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps := portforward.PermissionSet{}
			for _, p := range tc.set {
				ps.Add(p)
			}
			for _, params := range tc.matches {
				actual, ok := ps.Match(params.host, params.port)
				if params.fail {
					assert.False(t, ok)
					continue
				}
				if assert.True(t, ok) {
					assert.Same(t, tc.set[params.expected], actual)
				}
			}
		})
	}
}

func TestPermissionSet_AllEntries(t *testing.T) {
	ps := portforward.PermissionSet{}
	a := portforward.Permission{
		Context:       t.Context(),
		HostMatcher:   portforward.GlobHostMatcher("a"),
		RequestedPort: 1234,
	}
	b := portforward.Permission{
		Context:       t.Context(),
		HostMatcher:   portforward.GlobHostMatcher("b"),
		RequestedPort: 1234,
	}
	c := portforward.Permission{
		Context:       t.Context(),
		HostMatcher:   portforward.GlobHostMatcher("c"),
		RequestedPort: 1234,
	}
	ps.Add(&a)
	ps.Add(&b)
	ps.Add(&c)
	assert.Equal(t, []portforward.Permission{a, b, c}, slices.Collect(ps.AllEntries()))
	assert.Equal(t, []portforward.Permission{a, b}, slices.Collect(iterutil.Take(ps.AllEntries(), 2)))
}
