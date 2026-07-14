package authorize

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
)

// getMatchingPolicyByScan preserves the behavior of the linear scan replaced
// by indexPoliciesByRouteID.
func getMatchingPolicyByScan(opts *config.Options, routeID string) *config.Policy {
	for p := range opts.GetAllPolicies() {
		id, _ := p.RouteID()
		if id == routeID {
			return p
		}
	}
	return nil
}

func TestPolicyRouteIDIndexMatchesScan(t *testing.T) {
	t.Parallel()

	// dup.example.com/to1 hashes to one route ID; three policies share it,
	// deliberately spread across the three GetAllPolicies slices so that
	// first-wins has to reach across slice boundaries. AllowedUsers differ so
	// the "wrong" policy would be observable as an authz change.
	dupFrom := "https://dup.example.com"
	opts := &config.Options{
		Policies: []config.Policy{
			{
				From: dupFrom, AllowedUsers: []string{"alice@example.com"},
				To: mustParseWeightedURLs(t, "https://to1.example.com"),
			}, // FIRST duplicate -> should win
			{
				From: dupFrom, AllowedUsers: []string{"mallory@example.com"},
				To: mustParseWeightedURLs(t, "https://to1.example.com"),
			}, // second duplicate
		},
		Routes: []config.Policy{
			{
				From: "https://uniq.example.com",
				To:   mustParseWeightedURLs(t, "https://to2.example.com"),
			},
		},
		AdditionalPolicies: []config.Policy{
			{
				From: dupFrom, AllowedUsers: []string{"bob@example.com"},
				To: mustParseWeightedURLs(t, "https://to1.example.com"),
			}, // third duplicate
		},
	}

	idx := indexPoliciesByRouteID(t.Context(), opts)

	// For every buildable policy's route ID, the map must return exactly what
	// the old scan returned (identity, not just value equality).
	checked := 0
	for p := range opts.GetAllPolicies() {
		id, err := p.RouteID()
		if err != nil {
			continue
		}
		checked++
		want := getMatchingPolicyByScan(opts, id)
		got := idx[id]
		require.Samef(t, want, got, "route id %q: map returned a different policy than the scan", id)
	}
	require.Positive(t, checked)

	// The duplicate route ID must resolve to the FIRST policy in GetAllPolicies
	// order (Policies[0], the alice policy) under both scan and map.
	dupID, err := opts.Policies[0].RouteID()
	require.NoError(t, err)
	require.Same(t, &opts.Policies[0], idx[dupID])
	require.Same(t, &opts.Policies[0], getMatchingPolicyByScan(opts, dupID))
	require.Equal(t, []string{"alice@example.com"}, idx[dupID].AllowedUsers,
		"first-wins must pick alice, not mallory or bob")
}

// TestPolicyRouteIDIndexSkipsInvalidPolicyForEmptyRoute documents the one
// intentional difference from the old scan: a policy without a route action
// contributed an empty ID and could be selected for an internal route, even
// though the empty ID does not identify a policy.
func TestPolicyRouteIDIndexSkipsInvalidPolicyForEmptyRoute(t *testing.T) {
	t.Parallel()

	bad := config.Policy{From: "https://no-dest.example.com"} // no To/Redirect/Response
	_, err := bad.RouteID()
	require.Error(t, err, "sanity: this policy's RouteID must error")

	opts := &config.Options{
		Policies: []config.Policy{
			bad,
			{From: "https://ok.example.com", To: mustParseWeightedURLs(t, "https://to.example.com")},
		},
	}
	idx := indexPoliciesByRouteID(t.Context(), opts)

	// The errored policy is absent from the map for every non-error key.
	okID, err := opts.Policies[1].RouteID()
	require.NoError(t, err)
	require.Same(t, &opts.Policies[1], idx[okID])

	// The map has exactly one entry (the buildable policy); the errored one is skipped.
	require.Len(t, idx, 1)

	// Divergence is confined to the empty route ID used by internal routes: the
	// old scan returned the errored policy, while the map correctly returns no
	// policy because the empty ID does not identify one.
	require.Same(t, &opts.Policies[0], getMatchingPolicyByScan(opts, ""), "old scan matches errored policy on empty id")
	require.Nil(t, idx[""], "map returns nil on empty id")
}
