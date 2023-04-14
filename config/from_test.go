package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromRegexMatchesURL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		fromRegex  string
		requestURL string
		matches    bool
	}{
		{"invalid regexp", "[.", "https://www.example.com", false},
		{"anything", ".*", "https://www.example.com", true},
		{"exact", "^https://www[.]example[.]com$", "https://www.example.com", true},
		{"trailing", "^https://www[.]example[.]com/$", "https://www.example.com", true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u := mustParseWeightedURLs(t, tc.requestURL)[0].URL
			assert.Equal(t, tc.matches, FromRegexMatchesURL(tc.fromRegex, u))
		})
	}
}
