package evaluator

import (
	"context"
	"fmt"
	"os"
	"runtime/pprof"
	"testing"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/policy"
	"github.com/stretchr/testify/require"
)

func TestRegoCompiler_CompilePolicyQuery(t *testing.T) {
	compiler := NewRegoCompiler(store.New())
	for i := 1; i <= 4000; i++ {
		route := &config.Policy{
			From:         fmt.Sprintf("https://from-%d.example.com", i),
			To:           mustParseWeightedURLs(t, "https://to.example.com"),
			AllowedUsers: []string{fmt.Sprintf("user-%d", i)},
		}
		ppl := route.ToPPL()
		rego, err := policy.GenerateRegoFromPolicy(ppl)
		require.NoError(t, err)

		q, err := compiler.CompilePolicyQuery(context.Background(), rego)
		require.NoError(t, err)
		_ = q

		if i%1000 == 0 {
			writeHeapProfile(t, i)
		}
	}
}

func writeHeapProfile(t *testing.T, i int) {
	t.Helper()
	f, err := os.Create(fmt.Sprintf("heap-%d.out", i))
	require.NoError(t, err)
	err = pprof.WriteHeapProfile(f)
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)
}

func mustParseWeightedURLs(t *testing.T, urls ...string) []config.WeightedURL {
	t.Helper()

	wu, err := config.ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}
