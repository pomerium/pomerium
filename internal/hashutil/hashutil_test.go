// Package hashutil provides NON-CRYPTOGRAPHIC utility functions for hashing
package hashutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHash(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		v       any
		want    uint64
		wantErr bool
	}{
		{"string", "string", 6134271061086542852, false},
		{"num", 7, 609900476111905877, false},
		{
			"compound struct",
			struct {
				NESCarts      []string
				numberOfCarts int
			}{
				[]string{"Battletoads", "Mega Man 1", "Clash at Demonhead"},
				12,
			},
			1349584765528830812, false,
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
			if got := MustHash(tt.v); got != tt.want {
				t.Errorf("MustHash() = %v, want %v", got, tt.want)
			}
			got, err := Hash(tt.v)
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
