package cli

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/testutil"
	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

func TestConfig(t *testing.T) {
	cfg := newConfig()

	assert.Empty(t, cfg.getTags())
	assert.Empty(t, cfg.listAll())

	cfg.upsert(&pb.Record{
		Id:   testutil.StrP("a"),
		Tags: []string{"alpha", "bravo"},
	})
	cfg.upsert(&pb.Record{
		Id:   testutil.StrP("b"),
		Tags: []string{"go", "bravo"},
	})
	assert.Empty(t, cmp.Diff([]string{"alpha", "bravo", "go"},
		cfg.getTags(),
		cmpopts.SortSlices(func(a, b string) bool { return a < b })))

	cfg.delete("a")
	assert.Empty(t, cmp.Diff([]string{"bravo", "go"},
		cfg.getTags(),
		cmpopts.SortSlices(func(a, b string) bool { return a < b })))

	cfg.delete("b")
	assert.Empty(t, cfg.getTags())
	assert.Empty(t, cfg.listAll())
}
