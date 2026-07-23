package resolver

import "time"

// Refresh-ahead fractions and jitter, per §1.4 of the plan.
const (
	// renewableRefreshFraction is used for renewable leases (future Vault). The
	// constant exists now; no v1 provider reports renewable leases.
	renewableRefreshFraction = 0.66
	// nonRenewableRefreshFraction is used when the provider reports a TTL.
	nonRenewableRefreshFraction = 0.90
	// jitterFraction is the ±fraction of uniform jitter applied to every interval.
	jitterFraction = 0.10
	// minInterval is the hard floor: never refresh more often than this.
	minInterval = time.Second
)

// nextRefresh returns the absolute time of the next refresh attempt.
//
//	base = refreshInterval           if ttl <= 0 (flat poll, e.g. file://)
//	     = renewableFraction × ttl   if renewable lease
//	     = nonRenewableFraction × ttl otherwise
//
// The base is then jittered by ±jitterFraction (rnd returns [0,1); 0.5 => no
// jitter) and floored at minInterval.
func nextRefresh(now time.Time, ttl, refreshInterval time.Duration, renewable bool, rnd func() float64) time.Time {
	var base time.Duration
	switch {
	case ttl <= 0:
		base = refreshInterval
	case renewable:
		base = time.Duration(renewableRefreshFraction * float64(ttl))
	default:
		base = time.Duration(nonRenewableRefreshFraction * float64(ttl))
	}

	// rnd() in [0,1) maps to a jitter multiplier in [-jitterFraction, +jitterFraction);
	// 0.5 => no jitter.
	jitter := (rnd()*2 - 1) * jitterFraction
	d := max(time.Duration(float64(base)*(1+jitter)), minInterval)
	return now.Add(d)
}
