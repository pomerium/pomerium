// Package hashutil provides NON-CRYPTOGRAPHIC utility functions for hashing
package hashutil_test

import (
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
