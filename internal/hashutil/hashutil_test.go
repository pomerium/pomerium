package hashutil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/hashutil"
)

func TestHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		v       any
		want    uint64
		wantErr bool
	}{
		{"string", "string", 15613163272824911089, false},
		{"num", 7, 9324454920402081455, false},
		{
			"compound struct",
			struct {
				NESCarts      []string
				numberOfCarts int
			}{
				[]string{"Battletoads", "Mega Man 1", "Clash at Demonhead"},
				12,
			},
			9585735524299267794, false,
		},
		{
			"compound struct with embedded func (errors!)",
			struct {
				AnswerToEverythingFn func() int
			}{
				func() int { return 42 },
			},
			0, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hashutil.MustHash(tt.v); got != tt.want {
				t.Errorf("MustHash() = %v, want %v", got, tt.want)
			}
			got, err := hashutil.Hash(tt.v)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if got != tt.want {
				t.Errorf("Hash() = %v, want %v", got, tt.want)
			}
		})
	}
}
