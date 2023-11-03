package evaluator

import (
	"context"
	"fmt"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/policy"
	"github.com/stretchr/testify/require"
	"testing"
)

func BenchmarkRegoCompiler_CompilePolicyQuery(b *testing.B) {
	compiler := NewRegoCompiler(store.New())
	for i := 0; i < b.N; i++ {
		route := &config.Policy{
			From:         fmt.Sprintf("https://from-%d.example.com", i),
			To:           mustParseWeightedURLs(b, "https://to.example.com"),
			AllowedUsers: []string{fmt.Sprintf("user-%d", i)},
		}
		ppl := route.ToPPL()
		rego, err := policy.GenerateRegoFromPolicy(ppl)
		require.NoError(b, err)

		q, err := compiler.CompilePolicyQuery(context.Background(), rego)
		require.NoError(b, err)
		_ = q
	}

}

func mustParseWeightedURLs(t interface {
	require.TestingT
	Helper()
}, urls ...string) []config.WeightedURL {
	t.Helper()

	wu, err := config.ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}
