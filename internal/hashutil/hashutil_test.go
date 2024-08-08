// Package hashutil provides NON-CRYPTOGRAPHIC utility functions for hashing
package hashutil_test

import (
	"fmt"
	"math/rand/v2"
	"net/url"
	"testing"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/hashutil"
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

func TestHashCodec(t *testing.T) {
	policies1 := []config.Policy{
		{To: singleToURL("https://to1.example.com")},
		{To: singleToURL("https://to2.example.com")},
		{To: singleToURL("https://to3.example.com")},
		{To: singleToURL("https://to4.example.com")},
	}

	policies2 := []config.Policy{
		{To: singleToURL("https://to1.example.com")},
		{
			To:           singleToURL("https://to2.example.com"),
			AllowedUsers: []string{"user-id-1"},
		}, // change just the policy itself
		{To: singleToURL("https://to3.example.com")},
		{To: singleToURL("https://foo.example.com"), // change route ID too
			AllowAnyAuthenticatedUser: true},
	}

	assert.Equal(t, hashutil.MustHash(&policies1[0]), hashutil.MustHash(&policies2[0]))
	assert.NotEqual(t, hashutil.MustHash(&policies1[1]), hashutil.MustHash(&policies2[1]))
	assert.Equal(t, hashutil.MustHash(&policies1[2]), hashutil.MustHash(&policies2[2]))
	assert.NotEqual(t, hashutil.MustHash(&policies1[3]), hashutil.MustHash(&policies2[3]))
}

func singleToURL(url string) config.WeightedURLs {
	return config.WeightedURLs{{URL: *mustParseURL(url)}}
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}

func TestMapHash_Equal(t *testing.T) {
	t.Parallel()
	for _, elems := range []int{13, 50, 100, 1000} {
		t.Run(fmt.Sprintf("%d elements", elems), func(t *testing.T) {
			t.Parallel()
			numbers := make([]int64, elems)
			for i := range len(numbers) {
				numbers[i] = rand.Int64()
			}
			m := make(map[string]string, elems)
			for _, n := range numbers {
				m[fmt.Sprintf("key%d", n)] = fmt.Sprintf("value%d", n)
			}
			expected := hashutil.MapHash(0, m)
			for i := 0; i < 1000; i++ {
				rand.Shuffle(len(numbers), func(i, j int) {
					numbers[i], numbers[j] = numbers[j], numbers[i]
				})

				m := make(map[string]string, elems)
				for _, n := range numbers {
					m[fmt.Sprintf("key%d", n)] = fmt.Sprintf("value%d", n)
				}
				assert.Equal(t, expected, hashutil.MapHash(0, m))
			}
		})
	}
}

func TestMapHash_NotEqual(t *testing.T) {
	t.Parallel()
	t.Run("trivial cases", func(t *testing.T) {
		t.Parallel()
		a := map[string]string{"key1": "value1", "key2": "value2"}
		b := map[string]string{"key1": "value1"}
		assert.NotEqual(t, hashutil.MapHash(0, a), hashutil.MapHash(0, b))

		a = map[string]string{"key1": "value1", "key2": "value2"}
		b = map[string]string{"key1": "value1", "key2": "value3"}
		assert.NotEqual(t, hashutil.MapHash(0, a), hashutil.MapHash(0, b))

		a = map[string]string{"key1": "value1", "key2": "value2"}
		b = map[string]string{"key2": "value1", "key1": "value2"}
		assert.NotEqual(t, hashutil.MapHash(0, a), hashutil.MapHash(0, b))
	})

	for _, elems := range []int{1, 5, 10, 100, 1000} {
		t.Run(fmt.Sprintf("%d elements", elems), func(t *testing.T) {
			t.Parallel()
			seen := make(map[uint64]struct{}, 1000)
			for i := 0; i < 1000; i++ {
				numbers := make([]int64, elems)
				for i := range len(numbers) {
					numbers[i] = rand.Int64()
				}
				m := make(map[string]string, elems)
				mInverse := make(map[string]string, elems)
				mEqual := make(map[string]string, elems)
				for _, n := range numbers {
					m[fmt.Sprintf("key%d", n)] = fmt.Sprintf("value%d", n)
					mInverse[fmt.Sprintf("key%d", n)] = fmt.Sprintf("value%d", n)
					mEqual[fmt.Sprintf("%d", n)] = fmt.Sprintf("%d", n)
				}
				h := hashutil.MapHash(0, m)
				hInverse := hashutil.MapHash(0, mInverse)
				hEqual := hashutil.MapHash(0, mEqual)
				assert.NotContains(t, seen, h)
				assert.NotContains(t, seen, hInverse)
				assert.NotContains(t, seen, hEqual)
				seen[h] = struct{}{}
				seen[hInverse] = struct{}{}
				seen[hEqual] = struct{}{}
			}
		})
	}
}

func TestMapHash_IV(t *testing.T) {
	t.Parallel()
	for _, elems := range []int{5, 10, 100, 1000} {
		t.Run(fmt.Sprintf("%d elements", elems), func(t *testing.T) {
			t.Parallel()
			m := make(map[string]string, elems)
			for i := 0; i < elems; i++ {
				m[fmt.Sprintf("key%d", i)] = fmt.Sprintf("value%d", i)
			}
			seen := make(map[uint64]struct{}, 5000)
			for i := 0; i < 5000; i++ {
				h := hashutil.MapHash(rand.Uint64(), m)
				assert.NotContains(t, seen, h)
				seen[h] = struct{}{}
			}
		})
	}
}
