package agentic

import (
	"encoding/json"
	"fmt"
	"net/url"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/identity"
)

// maxExecutorClaims bounds the number of sealed executor claim attributes,
// keeping the run record and consent page bounded.
const maxExecutorClaims = 32

// volatileJWTClaims are the RFC 7519 claims excluded from the canonical
// encoding: they change on every token refresh for the same executor instance,
// and including them would break re-poll idempotency. This is generic JWT
// knowledge — no sandbox technology is assumed.
var volatileJWTClaims = map[string]struct{}{
	"iat": {}, "exp": {}, "nbf": {}, "jti": {},
}

// canonicalClaims deterministically encodes an executor claim set for the §12.8
// seal-match: the flattened claims minus the volatile RFC 7519 claims,
// url.Values-encoded (sorted keys, order-preserving multi-values). Comparing two
// canonical encodings is an order-independent, type-stable equality check that
// holds across the structpb.ListValue <-> decoded-JSON boundary. The sealed set
// is encoded at create and the presenting executor's projected claims at bind;
// per-instance distinction falls out of the claims themselves (e.g. a pod uid
// differs per pod), while a token refresh changes only the excluded claims.
func canonicalClaims(claims identity.FlattenedClaims) string {
	vals := url.Values{}
	for k, vs := range claims {
		if _, volatile := volatileJWTClaims[k]; volatile {
			continue
		}
		ss := make([]string, len(vs))
		for i, v := range vs {
			b, _ := json.Marshal(v)
			ss[i] = string(b)
		}
		vals[k] = ss
	}
	return vals.Encode()
}

// sealExecutor converts the caller-supplied expected executor identity subset
// into flattened claims to store as the run's bound_claims. It is required and
// non-empty: a run with no seal can never bind (§12.8). Each value is stored as
// a single-element list, mirroring the flattened-claims shape a verified token
// produces, so the bind-time seal-match compares like for like.
func sealExecutor(executor map[string]string) (identity.FlattenedClaims, error) {
	if len(executor) == 0 {
		return nil, fmt.Errorf("executor is required")
	}
	if len(executor) > maxExecutorClaims {
		return nil, fmt.Errorf("executor must have at most %d claims", maxExecutorClaims)
	}
	sealed := make(identity.FlattenedClaims, len(executor))
	for k, v := range executor {
		if k == "" || v == "" {
			return nil, fmt.Errorf("executor claims must have non-empty keys and values")
		}
		sealed[k] = []any{v}
	}
	return sealed, nil
}

// projectClaims returns the subset of claims whose keys appear in sealed. At
// bind time canonicalClaims(projectClaims(tokenClaims, run.BoundClaims)) must
// equal canonicalClaims of the sealed claims — the instance-pin check that the
// presenting executor carries exactly the sealed identity attributes with the
// sealed values.
func projectClaims(claims identity.FlattenedClaims, sealed map[string]*structpb.ListValue) identity.FlattenedClaims {
	out := make(identity.FlattenedClaims, len(sealed))
	for k := range sealed {
		if vs, ok := claims[k]; ok {
			out[k] = vs
		}
	}
	return out
}

// k8sExecutorSealKeys is the fixed set of flattened claim keys that identify a
// Kubernetes executor instance. The seal index (see sealIndexKey) is derived
// over exactly these keys so the /token handler can reconstruct a run's index
// key from a presenting workload token WITHOUT first knowing which run it
// belongs to — the token needs only prove who it is, not carry a run_id. These
// mirror the four kubernetes.io.* claims a kubelet-projected token carries.
var k8sExecutorSealKeys = []string{
	"kubernetes.io.namespace",
	"kubernetes.io.serviceaccount.name",
	"kubernetes.io.pod.name",
	"kubernetes.io.pod.uid",
}

// sealIndexKey derives the deterministic seal-index key from a claim set by
// projecting it onto the fixed executor key set (k8sExecutorSealKeys) and
// canonicalizing. At create the run's sealed claims yield the key; at bind the
// presenting token's claims yield the SAME key iff the token carries the sealed
// identity — so a run_id-less workload can locate its own run. It returns "" for
// a claim set that carries none of the executor keys (a non-k8s executor), which
// callers treat as "not indexable".
func sealIndexKey(claims identity.FlattenedClaims) string {
	projected := make(identity.FlattenedClaims, len(k8sExecutorSealKeys))
	for _, k := range k8sExecutorSealKeys {
		if vs, ok := claims[k]; ok {
			projected[k] = vs
		}
	}
	if len(projected) == 0 {
		return ""
	}
	return canonicalClaims(projected)
}
