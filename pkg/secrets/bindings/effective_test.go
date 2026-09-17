package bindings_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/secrets/bindings"
)

func TestScopeEffective(t *testing.T) {
	t.Parallel()

	reg := testRegistry(t)

	parent, err := bindings.NewScope(nil, []bindings.Binding{
		{ID: "shared", Ref: mustRef(t, "file:///parent")},
		{ID: "only-parent", Ref: mustRef(t, "file:///p")},
	}, stdDefaults(), reg)
	require.NoError(t, err)

	child, err := bindings.NewScope(parent, []bindings.Binding{
		{ID: "shared", Ref: mustRef(t, "file:///child")},
		{ID: "only-child", Ref: mustRef(t, "file:///c")},
	}, stdDefaults(), reg)
	require.NoError(t, err)

	eff := child.Effective()

	byID := make(map[string]string, len(eff))
	for _, b := range eff {
		byID[b.ID] = b.Ref.Key()
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	assert.Equal(t, []string{"only-child", "only-parent", "shared"}, ids)
	assert.Equal(t, "file:///child", byID["shared"], "leaf wins")
	assert.Equal(t, "file:///p", byID["only-parent"])
	assert.Equal(t, "file:///c", byID["only-child"])
}
