package sessions

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewContext(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		t    *State
		err  error
		want context.Context
	}{
		{"simple", context.Background(), &State{Email: "bdd@pomerium.io"}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctxOut := NewContext(tt.ctx, tt.t, tt.err)
			stateOut, errOut := FromContext(ctxOut)
			if diff := cmp.Diff(tt.t.Email, stateOut.Email); diff != "" {
				t.Errorf("NewContext() = %s", diff)
			}
			if diff := cmp.Diff(tt.err, errOut); diff != "" {
				t.Errorf("NewContext() = %s", diff)
			}
		})
	}
}

func Test_contextKey_String(t *testing.T) {
	tests := []struct {
		name    string
		keyName string
		want    string
	}{
		{"simple example", "test", "context value test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &contextKey{
				name: tt.keyName,
			}
			if got := k.String(); got != tt.want {
				t.Errorf("contextKey.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
