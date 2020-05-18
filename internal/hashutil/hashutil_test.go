// Package hashutil provides NON-CRYPTOGRAPHIC utility functions for hashing
package hashutil

import "testing"

func TestHash(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		v    interface{}
		want uint64
	}{
		{"string", "string", 6134271061086542852},
		{"num", 7, 609900476111905877},
		{"compound struct", struct {
			NESCarts      []string
			numberOfCarts int
		}{
			[]string{"Battletoads", "Mega Man 1", "Clash at Demonhead"},
			12,
		},
			9061978360207659575},
		{"compound struct with embedded func (errors!)", struct {
			AnswerToEverythingFn func() int
		}{
			func() int { return 42 },
		},
			0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Hash(tt.v); got != tt.want {
				t.Errorf("Hash() = %v, want %v", got, tt.want)
			}
		})
	}
}
