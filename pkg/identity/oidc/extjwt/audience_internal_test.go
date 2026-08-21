package extjwt

import (
	"testing"

	"hegel.dev/go/hegel"
)

// audienceMatches is the heart of the per-route audience binding (Verify
// rejects with ErrAudienceMismatch when it returns false). These property
// tests exercise the matcher across many generated inputs — empty sets,
// duplicates, unicode, arbitrary order — rather than the few hand-picked
// examples in the external test package.

// intersectsOracle is an independent reference for "do these two sets share an
// element": it uses a map, NOT the implementation's nested loop, so it can
// actually disagree with a buggy audienceMatches.
func intersectsOracle(have, want []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, h := range have {
		set[h] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; ok {
			return true
		}
	}
	return false
}

// TestAudienceMatches_OracleEquivalence is the core property: audienceMatches
// must agree with a map-based set-intersection oracle for any pair of slices.
func TestAudienceMatches_OracleEquivalence(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		have := hegel.Draw(ht, hegel.Lists(hegel.Text()))
		want := hegel.Draw(ht, hegel.Lists(hegel.Text()))

		got := audienceMatches(have, want)
		exp := intersectsOracle(have, want)
		if got != exp {
			ht.Fatalf("audienceMatches(%q, %q) = %v, oracle = %v", have, want, got, exp)
		}
	})
}

// TestAudienceMatches_Symmetric asserts intersection-non-emptiness is
// order-independent across the two arguments. The implementation iterates the
// first slice and scans the second, so an asymmetry would be a real bug.
func TestAudienceMatches_Symmetric(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		a := hegel.Draw(ht, hegel.Lists(hegel.Text()))
		b := hegel.Draw(ht, hegel.Lists(hegel.Text()))

		if audienceMatches(a, b) != audienceMatches(b, a) {
			ht.Fatalf("not symmetric: audienceMatches(%q,%q)=%v but audienceMatches(%q,%q)=%v",
				a, b, audienceMatches(a, b), b, a, audienceMatches(b, a))
		}
	})
}

// TestAudienceMatches_EmptyIsFalse asserts the fail-closed behavior of the
// matcher itself: an empty operand on either side can never match.
func TestAudienceMatches_EmptyIsFalse(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		xs := hegel.Draw(ht, hegel.Lists(hegel.Text()))

		if audienceMatches(nil, xs) {
			ht.Fatalf("audienceMatches(nil, %q) must be false", xs)
		}
		if audienceMatches(xs, nil) {
			ht.Fatalf("audienceMatches(%q, nil) must be false", xs)
		}
	})
}

// TestAudienceMatches_DuplicatesInert asserts that duplicate audiences don't
// change the verdict: matching against the de-duplicated inputs must give the
// same answer as matching against the originals.
func TestAudienceMatches_DuplicatesInert(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		have := hegel.Draw(ht, hegel.Lists(hegel.Text()))
		want := hegel.Draw(ht, hegel.Lists(hegel.Text()))

		dedup := func(xs []string) []string {
			seen := make(map[string]struct{}, len(xs))
			out := make([]string, 0, len(xs))
			for _, x := range xs {
				if _, ok := seen[x]; ok {
					continue
				}
				seen[x] = struct{}{}
				out = append(out, x)
			}
			return out
		}

		full := audienceMatches(have, want)
		deduped := audienceMatches(dedup(have), dedup(want))
		if full != deduped {
			ht.Fatalf("duplicates changed result: have=%q want=%q full=%v deduped=%v",
				have, want, full, deduped)
		}
	})
}
