package agentic

import (
	"encoding/json"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/identity"
)

// k8sClaims builds the flattened claims of a kubelet-projected token for the
// given pod uid, with the volatile timing claims set to the given epoch values.
func k8sClaims(t *testing.T, podUID string, iat, exp int64) identity.FlattenedClaims {
	t.Helper()
	raw := map[string]any{
		"iss": "https://kubernetes.default.svc.cluster.local",
		"sub": "system:serviceaccount:default:executor",
		"aud": []any{"pomerium-agentic-as"},
		"iat": iat,
		"exp": exp,
		"kubernetes.io": map[string]any{
			"namespace":      "default",
			"serviceaccount": map[string]any{"name": "executor"},
			"pod":            map[string]any{"name": "run-pod", "uid": podUID},
		},
	}
	// Round-trip through JSON so numbers take the float64 shape real JWT
	// parsing produces.
	bs, err := json.Marshal(raw)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(bs, &parsed))
	return identity.Claims(parsed).Flatten()
}

func TestCanonicalClaims_RefreshIdempotentInstanceDistinct(t *testing.T) {
	t.Parallel()

	original := canonicalClaims(k8sClaims(t, "pod-uid-1", 1000, 1600))
	refreshed := canonicalClaims(k8sClaims(t, "pod-uid-1", 2000, 2600))
	otherPod := canonicalClaims(k8sClaims(t, "pod-uid-2", 1000, 1600))

	assert.Equal(t, original, refreshed,
		"a token refresh (iat/exp change only) must produce the same canonical encoding")
	assert.NotEqual(t, original, otherPod,
		"a different pod uid must produce a different canonical encoding")
	assert.NotEmpty(t, original)
}

func TestSealExecutor(t *testing.T) {
	t.Parallel()

	_, err := sealExecutor(nil)
	assert.Error(t, err, "an empty executor must be rejected")
	_, err = sealExecutor(map[string]string{"": "v"})
	assert.Error(t, err, "an empty claim key must be rejected")
	_, err = sealExecutor(map[string]string{"k": ""})
	assert.Error(t, err, "an empty claim value must be rejected")

	sealed, err := sealExecutor(map[string]string{
		"kubernetes.io.serviceaccount.name": "executor",
		"kubernetes.io.pod.uid":             "pod-uid-1",
	})
	require.NoError(t, err)
	assert.Equal(t, []any{"executor"}, sealed["kubernetes.io.serviceaccount.name"])
}

// TestSealMatch is the instance-pin check (§12.8): the executor a run is sealed
// to binds (across token refreshes), and no other instance — even one under the
// same service account — reproduces the seal.
func TestSealMatch(t *testing.T) {
	t.Parallel()

	sealed, err := sealExecutor(map[string]string{
		"kubernetes.io.namespace":           "default",
		"kubernetes.io.serviceaccount.name": "executor",
		"kubernetes.io.pod.name":            "run-pod",
		"kubernetes.io.pod.uid":             "pod-uid-1",
	})
	require.NoError(t, err)
	seal := canonicalClaims(sealed)
	boundClaims := sealed.ToPB()

	// The handler recomputes the sealed side from the stored bound_claims; that
	// round-trip must reproduce the seal computed from the original claims.
	assert.Equal(t, seal, canonicalClaims(identity.NewFlattenedClaimsFromPB(boundClaims)),
		"the sealed claims, round-tripped through protobuf, must reproduce the seal")

	matched := canonicalClaims(projectClaims(k8sClaims(t, "pod-uid-1", 2000, 2600), boundClaims))
	assert.Equal(t, seal, matched, "the sealed executor instance (any refresh) must reproduce the seal")

	mismatch := canonicalClaims(projectClaims(k8sClaims(t, "pod-uid-2", 1000, 1600), boundClaims))
	assert.NotEqual(t, seal, mismatch, "a different pod instance must not reproduce the seal")
}

func TestSealIndexKeyRequiresACompleteSeal(t *testing.T) {
	t.Parallel()

	complete := identity.FlattenedClaims{
		"kubernetes.io.namespace":           []any{"default"},
		"kubernetes.io.serviceaccount.name": []any{"executor"},
		"kubernetes.io.pod.name":            []any{"run-pod"},
		"kubernetes.io.pod.uid":             []any{"pod-uid-1"},
	}

	// A workload token carries all four claims, so a run sealed to all four is
	// found under the same key the token derives.
	full := sealIndexKey(complete)
	require.NotEmpty(t, full)
	assert.Equal(t, full, sealIndexKey(complete), "the key must be deterministic")

	// A token carrying extra claims still derives the same key: the projection
	// is over the fixed key set.
	withExtras := maps.Clone(complete)
	withExtras["sub"] = []any{"system:serviceaccount:default:executor"}
	withExtras["iat"] = []any{1234}
	assert.Equal(t, full, sealIndexKey(withExtras),
		"claims outside the fixed key set must not change the index")

	// A partial seal is NOT indexable. Indexing the sealed subset would store the
	// run under a key no presenting token can ever derive, and the run would be
	// permanently unresolvable in the run_id-less flow.
	for _, omit := range slices.Sorted(maps.Keys(complete)) {
		partial := maps.Clone(complete)
		delete(partial, omit)
		assert.Empty(t, sealIndexKey(partial),
			"a seal missing %s must not be indexable", omit)
	}

	// A non-k8s executor carries none of the keys and is likewise not indexable.
	assert.Empty(t, sealIndexKey(identity.FlattenedClaims{"sub": []any{"spiffe://x"}}))
}
