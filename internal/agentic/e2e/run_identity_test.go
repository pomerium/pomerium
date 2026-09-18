// Package e2e exercises the agentic run-identity flow end-to-end against a real
// Pomerium test environment: the routes that authorize the authorization server,
// the interactive approval that every run now requires, and the run token's use
// at a target route.
package e2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
)

// workloadAudience is the audience the mock issuer accepts and the tests mint
// workload tokens for.
const workloadAudience = "pomerium.example.com"

// configureJWTIdp wires a mock OIDC issuer into Pomerium's identity_providers
// map under the given name and returns the IDP plus its issuer URL. (Adapted
// from authorize's jwt_bearer_int_test.go, whose helpers are private to that
// test package.)
func configureJWTIdp(t *testing.T, env testenv.Environment, idpName string) (*mockidp.IDP, values.Value[string]) {
	t.Helper()

	idp := mockidp.New(mockidp.Config{})
	idpUp := upstreams.HTTP(nil, upstreams.WithDisplayName("JWT Issuer"))
	idp.Register(idpUp.Router())
	env.AddUpstream(idpUp)

	idpURL := values.Bind(idpUp.Addr(), func(addr string) string {
		return fmt.Sprintf("http://%s", addr)
	})

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.IdentityProviders == nil {
			cfg.Options.IdentityProviders = map[string]config.IdentityProvider{}
		}
		cfg.Options.IdentityProviders[idpName] = config.IdentityProvider{
			Issuer:        idpURL.Value(),
			Audiences:     []string{workloadAudience},
			SupportedAlgs: []string{"ES256"}, // mockidp signs with ES256
		}
	}))

	return idp, idpURL
}

// TestAgenticASIsAuthorizedByItsRoutes proves the property the whole design rests
// on: the authorization server has no authorization of its own, so the routes in
// front of it are the only thing deciding who may summon a run, who may exchange a
// token for one, and who may read a run's status.
//
// Everything here is checked WITHOUT an approval, because none of it should
// depend on one — a caller the summon policy does not admit must be stopped
// before the AS is ever reached.
func TestAgenticASIsAuthorizedByItsRoutes(t *testing.T) {
	env := testenv.New(t)
	idp, idpURL := configureJWTIdp(t, env, "cluster")

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagAgentic] = true
	}))

	up := upstreams.HTTP(nil, upstreams.WithDisplayName("Echo"))
	up.Handle("/echo", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	// The admin's two statements. Only the harness service account may summon;
	// only a sandbox-agent pod may exchange. Note the exchange policy names no
	// specific pod — it admits the whole class, which is exactly why the seal, not
	// this policy, is what ties one approval to one instance.
	const summonPolicy = `{"allow":{"and":[
		{"claim/sub": "system:serviceaccount:default:harness"}]}}`
	const exchangePolicy = `{"allow":{"and":[
		{"claim/kubernetes.io.namespace": "default"},
		{"claim/kubernetes.io.serviceaccount.name": "sandbox-agent"}]}}`
	const approvePolicy = `{"allow":{"and":[{"domain": "example.com"}]}}`

	as := newAgenticRoutes(t, env, "cluster", summonPolicy, exchangePolicy, approvePolicy)

	// A plain route on a different host, used to show the AS answers nowhere else.
	toAddr := values.Bind(up.Addr(), func(addr string) string {
		return fmt.Sprintf("http://%s", addr)
	})
	plain := up.Route().From(env.SubdomainURL("plain")).To(toAddr).
		PPL(`{"allow":{"and":[{"claim/sub": "system:serviceaccount:default:harness"}]}}`)

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	now := time.Now()
	jwtFor := func(sub string, k8s map[string]any) string {
		return workloadJWT(idp, idpURL.Value(), sub, now, k8s)
	}

	harnessJWT := jwtFor("system:serviceaccount:default:harness", nil)
	otherWorkloadJWT := jwtFor("system:serviceaccount:default:someone-else", nil)
	executorJWT := jwtFor("system:serviceaccount:default:sandbox-agent",
		podClaims("sandbox-agent", "run-pod-1", "pod-uid-1"))

	newRunBody := func() map[string]any {
		return map[string]any{
			"ttl_seconds": 600,
			"prompt":      "do the thing",
			"executor":    executorSeal("sandbox-agent", "run-pod-1", "pod-uid-1"),
		}
	}

	// --- 1. The summon policy is what admits a caller. ---
	resp, body := postJSON(t, up, as.summon, runsPath, bearer(harnessJWT), newRunBody())
	require.Equal(t, http.StatusCreated, resp.StatusCode, "the admitted summoner must be able to create a run: %v", body)
	runID, _ := body["run_id"].(string)
	require.NotEmpty(t, runID)

	// Every run is created pending: there is no shape in which a run exists that a
	// human did not approve, which is what makes act.* on a route mean consent.
	approvalURL, _ := body["approval_url"].(string)
	assert.Contains(t, approvalURL, approvePath+"?run_id=",
		"every run must come with an approval URL")
	assert.Contains(t, approvalURL, as.summon.URL().Value(),
		"the approval URL must name the public agentic host, not the AS's loopback listener")

	resp, _ = postJSON(t, up, as.summon, runsPath, bearer(otherWorkloadJWT), newRunBody())
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"a workload the summon policy does not admit must be refused before the AS is reached")

	// No credential at all is a browser-shaped request, so it is answered with a
	// sign-in redirect rather than a status; all that matters is that no run is
	// created.
	resp, _ = postJSON(t, up, as.summon, runsPath, nil, newRunBody())
	assert.NotEqual(t, http.StatusCreated, resp.StatusCode, "an unauthenticated create must not create a run")

	// --- 1b. An executor token is not a summoning credential. It verifies, but the
	// summon policy does not admit it. ---
	resp, _ = postJSON(t, up, as.summon, runsPath, bearer(executorJWT), newRunBody())
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"the exchange credential must not also be a summoning credential")

	// --- 1c. A run must be pinned to an executor instance at creation. ---
	resp, body = postJSON(t, up, as.summon, runsPath, bearer(harnessJWT), map[string]any{
		"ttl_seconds": 600,
	})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "create without an executor must be 400: %v", body)

	// --- 1d. Labels are display-only, but they land on a record and a page a human
	// reads, so their size is bounded. ---
	oversized := newRunBody()
	oversized["labels"] = map[string]any{strings.Repeat("k", 65): "v"}
	resp, body = postJSON(t, up, as.summon, runsPath, bearer(harnessJWT), oversized)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "an over-long label key must be 400: %v", body)

	// --- 2. A run's status is disclosed to its creator only. ---
	statusResp, st := getRunStatus(t, up, as.summon, harnessJWT, runID)
	require.Equal(t, http.StatusOK, statusResp.StatusCode, "the creator must be able to read its run: %v", st)
	assert.Equal(t, "pending_approval", st["state"])

	statusResp, _ = getRunStatus(t, up, as.summon, harnessJWT, "00000000-0000-0000-0000-000000000000")
	assert.Equal(t, http.StatusNotFound, statusResp.StatusCode, "an unknown run id must be 404")

	// --- 3. The exchange policy is what admits an executor. ---
	resp, body = postJSON(t, up, as.token, tokenPath, bearer(executorJWT), map[string]any{})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"the admitted executor reaches the AS, which reports the run is not yet approved: %v", body)
	assert.Equal(t, "authorization_pending", body["error"])

	resp, _ = postJSON(t, up, as.token, tokenPath, bearer(harnessJWT), map[string]any{})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"the summoner's own credential must not be able to exchange a token")

	// An unattested token — one minted for the service account directly, carrying
	// no pod claims — satisfies the exchange policy, because the policy names the
	// class and nothing else. It is the seal that refuses it: with no pod claims
	// its seal-index key matches no run, so it never binds one.
	//
	// The exchange route deliberately does NOT try to require attestation itself.
	// A route policy cannot: `claim/` reads the session's claims UNIONED with the
	// user record's, and the user record is keyed by subject and only ever merged
	// into — so once one pod's token has stamped a pod claim onto the shared
	// service account's record, a later token from that account without one still
	// satisfies any test for it. Attestation is checked where the presenting
	// token's own claims are, which never goes near PPL.
	resp, body = postJSON(t, up, as.token, tokenPath,
		bearer(jwtFor("system:serviceaccount:default:sandbox-agent", map[string]any{
			"namespace":      "default",
			"serviceaccount": map[string]any{"name": "sandbox-agent"},
		})), map[string]any{})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"an unattested token (no pod claims) must bind no run: %v", body)
	assert.Equal(t, "authorization_pending", body["error"],
		"an unattested token must be told no run is sealed to it, not handed one")

	// --- 4. The endpoints answer nowhere else. The old mount is gone, and the AS's
	// paths on a host with no agentic route are just that host's paths. ---
	resp, _ = postJSON(t, up, plain, "/.pomerium/agentic/runs", bearer(harnessJWT), newRunBody())
	assert.NotEqual(t, http.StatusCreated, resp.StatusCode,
		"the old unauthorized /.pomerium/agentic mount must be gone")

	resp, _ = postJSON(t, up, plain, runsPath, bearer(harnessJWT), newRunBody())
	assert.NotEqual(t, http.StatusCreated, resp.StatusCode,
		"the AS must not answer on a host that has no route pointing at it")
}
