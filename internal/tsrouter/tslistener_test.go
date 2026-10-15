package tsrouter

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestTSListenerEqual(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		x, y   *tsListener
		expect bool
	}{
		{&tsListener{}, &tsListener{}, true},
		{nil, nil, true},
		{&tsListener{}, nil, false},
		{nil, &tsListener{}, false},
		{
			&tsListener{Settings: config.TailscaleListenerSettings{
				AuthKey: nullable.From("test"),
			}},
			&tsListener{Settings: config.TailscaleListenerSettings{
				AuthKey: nullable.From("test"),
			}},
			true,
		},
	} {
		x, _ := json.MarshalIndent(tc.x, "", "  ")
		y, _ := json.MarshalIndent(tc.y, "", "  ")
		assert.Equal(t, tc.expect, tc.x.Equal(tc.y), "%s, %s", x, y)
	}
}
