package jwtutil

import (
	"encoding/json"
	"slices"
	"strconv"
	"testing"

	"hegel.dev/go/hegel"
)

// These property tests cover the `aud`-claim normalization that underpins JWT
// bearer audience matching: a JWT `aud` may be a single string OR an array of
// strings, and toStringSlice (via the exported GetStringSlice/GetAudience)
// must handle both — plus arbitrary, attacker-controlled claim values — without
// panicking. See pkg/identity/oidc/extjwt for the matching step that consumes
// these normalized audiences.

// TestGetAudience_SingleStringIsSingleton asserts the single-string `aud` form
// normalizes to a one-element slice (the form used by many OIDC issuers).
func TestGetAudience_SingleStringIsSingleton(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		s := hegel.Draw(ht, hegel.Text())

		got, ok := Claims{"aud": s}.GetAudience()
		if !ok {
			ht.Fatalf("GetAudience ok=false for present aud=%q", s)
		}
		if !slices.Equal(got, []string{s}) {
			ht.Fatalf("single-string aud=%q normalized to %q, want [%q]", s, got, s)
		}
	})
}

// TestGetStringSlice_StringSliceIdentity asserts that an array-of-strings claim
// round-trips element-for-element with no loss or reordering.
func TestGetStringSlice_StringSliceIdentity(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		xs := hegel.Draw(ht, hegel.Lists(hegel.Text()))

		got, ok := Claims{"k": xs}.GetStringSlice("k")
		if !ok {
			ht.Fatalf("GetStringSlice ok=false for present key")
		}
		if !slices.Equal(got, xs) {
			ht.Fatalf("[]string identity broken: in=%q out=%q", xs, got)
		}
	})
}

// TestToStringSlice_LengthContract asserts the output-length contract:
// a slice input preserves its length, a non-slice input yields exactly one
// element.
func TestToStringSlice_LengthContract(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		// Slice case: mixed element types, length must be preserved.
		n := hegel.Draw(ht, hegel.Integers(0, 20))
		input := make([]any, 0, n)
		for range n {
			switch hegel.Draw(ht, hegel.Integers(0, 2)) {
			case 0:
				input = append(input, hegel.Draw(ht, hegel.Text()))
			case 1:
				input = append(input, hegel.Draw(ht, hegel.Integers(-1000, 1000)))
			default:
				input = append(input, hegel.Draw(ht, hegel.Booleans()))
			}
		}
		if got := toStringSlice(input); len(got) != len(input) {
			ht.Fatalf("slice length not preserved: in len=%d out len=%d (%q)", len(input), len(got), got)
		}

		// Non-slice case: a scalar must produce a single-element slice.
		scalar := hegel.Draw(ht, hegel.Integers(-1000, 1000))
		if got := toStringSlice(scalar); len(got) != 1 {
			ht.Fatalf("non-slice scalar %d produced %d elements: %q", scalar, len(got), got)
		}
	})
}

// drawClaimValue builds an arbitrary JSON-shaped claim value: strings,
// json.Number (the form UnmarshalJSON produces for numbers), plain ints,
// booleans, nil, and nested []any up to the given depth.
func drawClaimValue(ht *hegel.T, depth int) any {
	maxKind := 4
	if depth > 0 {
		maxKind = 5 // allow a nested slice only while depth remains
	}
	switch hegel.Draw(ht, hegel.Integers(0, maxKind)) {
	case 0:
		return hegel.Draw(ht, hegel.Text())
	case 1:
		return json.Number(strconv.Itoa(hegel.Draw(ht, hegel.Integers(-100000, 100000))))
	case 2:
		return hegel.Draw(ht, hegel.Booleans())
	case 3:
		return nil
	case 4:
		return hegel.Draw(ht, hegel.Integers(-100000, 100000))
	default: // 5: nested slice
		n := hegel.Draw(ht, hegel.Integers(0, 5))
		xs := make([]any, 0, n)
		for range n {
			xs = append(xs, drawClaimValue(ht, depth-1))
		}
		return xs
	}
}

// TestGetStringSlice_NoCrashArbitrary is the robustness property: claim values
// are attacker-controlled, so normalization must never panic and must always
// return a non-nil slice for a present key, whatever the value's shape.
func TestGetStringSlice_NoCrashArbitrary(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		v := drawClaimValue(ht, 3)

		got, ok := Claims{"x": v}.GetStringSlice("x")
		if !ok {
			ht.Fatalf("ok=false for present key (value=%#v)", v)
		}
		if got == nil {
			ht.Fatalf("nil slice for present key (value=%#v)", v)
		}
	})
}

// TestGetAudience_MatchesGetStringSlice asserts the two related APIs agree:
// GetAudience must be exactly GetStringSlice("aud"), and `ok` must reflect
// whether the aud key is present.
func TestGetAudience_MatchesGetStringSlice(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		present := hegel.Draw(ht, hegel.Booleans())
		claims := Claims{}
		if present {
			claims["aud"] = drawClaimValue(ht, 2)
		}

		a, aok := claims.GetAudience()
		b, bok := claims.GetStringSlice("aud")
		if aok != bok {
			ht.Fatalf("ok mismatch: GetAudience ok=%v, GetStringSlice ok=%v", aok, bok)
		}
		if !slices.Equal(a, b) {
			ht.Fatalf("value mismatch: GetAudience=%q, GetStringSlice=%q", a, b)
		}
		if aok != present {
			ht.Fatalf("ok=%v but key present=%v", aok, present)
		}
	})
}
