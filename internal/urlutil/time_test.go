package urlutil

import (
	"fmt"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildTimeParameters(t *testing.T) {
	t.Parallel()

	params := make(url.Values)
	BuildTimeParameters(params, time.Minute)
	assert.True(t, params.Has(QueryIssued))
	assert.True(t, params.Has(QueryExpiry))

	ms1, _ := strconv.Atoi(params.Get(QueryIssued))
	ms2, _ := strconv.Atoi(params.Get(QueryExpiry))
	assert.Equal(t, 60000, ms2-ms1)
}

func TestValidateTimeParameters(t *testing.T) {
	t.Parallel()

	msNow := time.Now().UnixMilli()
	for _, tc := range []struct {
		name   string
		params url.Values
		err    string
	}{
		{"empty", url.Values{}, "invalid issued timestamp"},
		{"missing issued", url.Values{QueryExpiry: {fmt.Sprint(msNow + 10000)}}, "invalid issued timestamp"},
		{"missing expiry", url.Values{QueryIssued: {fmt.Sprint(msNow + 10000)}}, "invalid expiry timestamp"},
		{"invalid issued", url.Values{
			QueryIssued: {fmt.Sprint(msNow + 120000)},
			QueryExpiry: {fmt.Sprint(msNow + 240000)},
		}, "issued in the future"},
		{"invalid expiry", url.Values{
			QueryIssued: {fmt.Sprint(msNow - 120000)},
			QueryExpiry: {fmt.Sprint(msNow - 240000)},
		}, "expired"},
		{"valid", url.Values{
			QueryIssued: {fmt.Sprint(msNow)},
			QueryExpiry: {fmt.Sprint(msNow)},
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateTimeParameters(tc.params)
			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}
