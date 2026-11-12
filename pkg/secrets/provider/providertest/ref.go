package providertest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// MustParseRef parses raw as a secret ref, failing the test on error.
func MustParseRef(tb testing.TB, raw string) ref.Ref {
	tb.Helper()
	r, err := ref.Parse(raw)
	require.NoError(tb, err)
	return r
}
