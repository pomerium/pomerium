package pkce

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestWithPKCE(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params Params
	}{
		{
			name: "valid params with S256",
			params: Params{
				Verifier: "test-verifier",
				Method:   "S256",
			},
		},
		{
			name: "valid params with plain",
			params: Params{
				Verifier: "test-verifier",
				Method:   "plain",
			},
		},
		{
			name: "empty verifier",
			params: Params{
				Verifier: "",
				Method:   "S256",
			},
		},
		{
			name: "empty method",
			params: Params{
				Verifier: "test-verifier",
				Method:   "",
			},
		},
		{
			name:   "empty params",
			params: Params{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			ctx = WithPKCE(ctx, tt.params)
			assert.NotNil(t, ctx)

			// Verify the context has the value
			val := ctx.Value(pkceContextKey{})
			assert.NotNil(t, val)
			params, ok := val.(Params)
			require.True(t, ok)
			assert.Equal(t, tt.params, params)
		})
	}
}

func TestFromContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		ctx        context.Context
		wantParams Params
		wantOK     bool
	}{
		{
			name: "valid params with S256",
			ctx: WithPKCE(context.Background(), Params{
				Verifier: "test-verifier",
				Method:   "S256",
			}),
			wantParams: Params{
				Verifier: "test-verifier",
				Method:   "S256",
			},
			wantOK: true,
		},
		{
			name: "valid params with plain",
			ctx: WithPKCE(context.Background(), Params{
				Verifier: "test-verifier",
				Method:   "plain",
			}),
			wantParams: Params{
				Verifier: "test-verifier",
				Method:   "plain",
			},
			wantOK: true,
		},
		{
			name: "empty verifier returns false",
			ctx: WithPKCE(context.Background(), Params{
				Verifier: "",
				Method:   "S256",
			}),
			wantParams: Params{},
			wantOK:     false,
		},
		{
			name: "empty method still returns true if verifier present",
			ctx: WithPKCE(context.Background(), Params{
				Verifier: "test-verifier",
				Method:   "",
			}),
			wantParams: Params{
				Verifier: "test-verifier",
				Method:   "",
			},
			wantOK: true,
		},
		{
			name:       "empty params returns false",
			ctx:        WithPKCE(context.Background(), Params{}),
			wantParams: Params{},
			wantOK:     false,
		},
		{
			name:       "no params in context",
			ctx:        context.Background(),
			wantParams: Params{},
			wantOK:     false,
		},
		{
			name:       "wrong type in context",
			ctx:        context.WithValue(context.Background(), pkceContextKey{}, "wrong-type"),
			wantParams: Params{},
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			params, ok := FromContext(tt.ctx)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantParams, params)
		})
	}
}

func TestWithPKCE_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params Params
		wantOK bool
	}{
		{
			name: "S256 round-trips",
			params: Params{
				Verifier: "test-verifier-12345",
				Method:   "S256",
			},
			wantOK: true,
		},
		{
			name: "plain round-trips",
			params: Params{
				Verifier: "plain-verifier",
				Method:   "plain",
			},
			wantOK: true,
		},
		{
			name: "empty verifier does not round-trip",
			params: Params{
				Verifier: "",
				Method:   "S256",
			},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			ctx = WithPKCE(ctx, tt.params)
			params, ok := FromContext(ctx)

			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.params, params)
			} else {
				assert.Equal(t, Params{}, params)
			}
		})
	}
}

func TestAuthCodeOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		params   Params
		wantNil  bool
		wantLen  int
		checkVal bool
	}{
		{
			name: "S256 returns challenge option",
			params: Params{
				Verifier: "test-verifier",
				Method:   "S256",
			},
			wantNil:  false,
			wantLen:  1,
			checkVal: true,
		},
		{
			name: "s256 lowercase returns challenge option",
			params: Params{
				Verifier: "test-verifier",
				Method:   "s256",
			},
			wantNil:  false,
			wantLen:  1,
			checkVal: true,
		},
		{
			name: "S256 mixed case returns challenge option",
			params: Params{
				Verifier: "test-verifier",
				Method:   "S256",
			},
			wantNil:  false,
			wantLen:  1,
			checkVal: true,
		},
		{
			name: "plain method returns nil",
			params: Params{
				Verifier: "test-verifier",
				Method:   "plain",
			},
			wantNil: true,
		},
		{
			name: "PLAIN uppercase returns nil",
			params: Params{
				Verifier: "test-verifier",
				Method:   "PLAIN",
			},
			wantNil: true,
		},
		{
			name: "empty verifier returns nil",
			params: Params{
				Verifier: "",
				Method:   "S256",
			},
			wantNil: true,
		},
		{
			name: "empty method returns nil",
			params: Params{
				Verifier: "test-verifier",
				Method:   "",
			},
			wantNil: true,
		},
		{
			name:    "empty params returns nil",
			params:  Params{},
			wantNil: true,
		},
		{
			name: "unknown method returns nil",
			params: Params{
				Verifier: "test-verifier",
				Method:   "unknown",
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := AuthCodeOptions(tt.params)

			if tt.wantNil {
				assert.Nil(t, opts)
			} else {
				require.NotNil(t, opts)
				assert.Len(t, opts, tt.wantLen)
				if tt.checkVal {
					// Verify it's an S256 challenge option
					expected := oauth2.S256ChallengeOption(tt.params.Verifier)
					assert.Equal(t, expected, opts[0])
				}
			}
		})
	}
}

func TestVerifierOption(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		params   Params
		wantOK   bool
		checkVal bool
	}{
		{
			name: "valid verifier with S256",
			params: Params{
				Verifier: "test-verifier",
				Method:   "S256",
			},
			wantOK:   true,
			checkVal: true,
		},
		{
			name: "valid verifier with plain",
			params: Params{
				Verifier: "test-verifier",
				Method:   "plain",
			},
			wantOK:   true,
			checkVal: true,
		},
		{
			name: "valid verifier with empty method",
			params: Params{
				Verifier: "test-verifier",
				Method:   "",
			},
			wantOK:   true,
			checkVal: true,
		},
		{
			name: "empty verifier returns nil and false",
			params: Params{
				Verifier: "",
				Method:   "S256",
			},
			wantOK: false,
		},
		{
			name:   "empty params returns nil and false",
			params: Params{},
			wantOK: false,
		},
		{
			name: "long verifier",
			params: Params{
				Verifier: "very-long-verifier-string-that-should-still-work-correctly",
				Method:   "S256",
			},
			wantOK:   true,
			checkVal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opt, ok := VerifierOption(tt.params)

			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				require.NotNil(t, opt)
				if tt.checkVal {
					// Verify it's a verifier option
					expected := oauth2.VerifierOption(tt.params.Verifier)
					assert.Equal(t, expected, opt)
				}
			} else {
				assert.Nil(t, opt)
			}
		})
	}
}

type mockProvider struct {
	methods []string
}

func (mp mockProvider) PKCEMethods() []string {
	return mp.methods
}

func TestMethodsProvider(t *testing.T) {
	t.Parallel()

	// Test that the interface is implemented correctly
	mp := mockProvider{methods: []string{"S256", "plain"}}
	var _ MethodsProvider = mp

	// Verify the mock works
	assert.Equal(t, []string{"S256", "plain"}, mp.PKCEMethods())
}
