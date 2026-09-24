package e2e

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/agentic"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	idpsessionpb "github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/nullable"
)

// TestRunIdentityInteractiveApproval drives the CIBA-style interactive approval
// flow: a run is created PENDING with a human-readable prompt, the executor's
// token poll returns authorization_pending until a signed-in browser user opens
// the consent page and approves, and the run token then acts with the approving
// user's authority. It also proves binding and approval are order-independent
// and that the approver's identity (not anything static) drives PPL authority.
func TestRunIdentityInteractiveApproval(t *testing.T) {
	env := testenv.New(t)
	idp, idpURL := configureJWTIdp(t, env, "workload")

	// Interactive browser-SSO IdP (the main provider) for the human approver.
	// This coexists with the workload identity_providers config above — they are
	// different subsystems (browser SSO vs. workload JWT verification).
	// The pointers are retained: mockidp.New assigns each user's ID (the IdP `sub`)
	// in place, and Pomerium's session UserId — the `sub` on the assertion the
	// approve handler reads — is that value verbatim. Holding them is the only way
	// to state an expected_subject in a test, and it doubles as a check that
	// expected_subject really is the raw IdP subject rather than an email.
	alice := &scenarios.User{Email: "alice@example.com"}
	mallory := &scenarios.User{Email: "mallory@example.com"}
	env.Add(scenarios.NewIDP([]*scenarios.User{alice, mallory}))

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

	// routeA admits an alice-approved run bound to pod-uid-1. routeB carries the
	// same shape pinned to a pod that does not exist, because scope is now the
	// route's own statement about who may reach it: the run no longer carries a
	// grant, so a route that does not want this agent says so in its own policy.
	const runPPL = `{"allow":{"and":[
		{"claim/email": "alice@example.com"},
		{"claim/act.kubernetes.io.pod.uid": "pod-uid-1"}]}}`
	const otherRunPPL = `{"allow":{"and":[
		{"claim/email": "alice@example.com"},
		{"claim/act.kubernetes.io.pod.uid": "pod-uid-does-not-exist"}]}}`

	toAddr := values.Bind(up.Addr(), func(addr string) string {
		return fmt.Sprintf("http://%s", addr)
	})
	// Both routes explicitly opt into run-token acceptance. Setting the format
	// leaves the cookie-based browser consent flow untouched: with no run token in
	// the request, resolution yields ErrNoSessionFound and falls through to the
	// session cookie.
	acceptsRunToken := func(p *config.Policy) {
		p.BearerTokenFormat = nullable.From(configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_AGENTIC_RUN_TOKEN)
	}
	routeA := up.Route().From(env.SubdomainURL("api")).To(toAddr).PPL(runPPL).Policy(acceptsRunToken)
	routeB := up.Route().From(env.SubdomainURL("other")).To(toAddr).PPL(otherRunPPL).Policy(acceptsRunToken)
	// routeC's PPL is satisfiable by the same run, but it declares no
	// bearer_token_format, so it must never interpret a run token: acceptance is
	// something a route opts into, not something a token asserts.
	routeC := up.Route().From(env.SubdomainURL("public")).To(toAddr).PPL(runPPL)

	// The three routes the AS itself sits behind.
	as := newAgenticRoutes(t, env, "workload",
		`{"allow":{"and":[{"claim/sub": "system:serviceaccount:default:harness"}]}}`,
		`{"allow":{"and":[
			{"claim/kubernetes.io.serviceaccount.name": "executor"}]}}`,
		`{"allow":{"and":[{"domain": "example.com"}]}}`)

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	now := time.Now()
	harnessJWT := workloadJWT(idp, idpURL.Value(), "system:serviceaccount:default:harness", now, nil)
	sidecarJWT := func(podUID string) string {
		return workloadJWT(idp, idpURL.Value(), "system:serviceaccount:default:executor", now,
			podClaims("executor", "run-pod-1", podUID))
	}

	// createPendingRun creates an approval-required run scoped to routeA, sealed to
	// the given pod uid, and returns its id. Distinct runs must seal to distinct pods
	// (one executor instance ↔ one run), since a pod resolves its run by identity alone.
	// createPinnedRun is createPendingRun with an expected_subject. Empty leaves the
	// run approvable by anyone the route admits, which is createPendingRun.
	createPinnedRun := func(prompt, podUID, expectedSubject string) (runID, approvalURL string) {
		fields := map[string]any{
			"ttl_seconds": 600,
			"prompt":      prompt,
			"executor":    executorSeal("executor", "run-pod-1", podUID),
			// A disclosure of the capabilities the approval exposes, not a grant.
			"mcp_servers": []string{routeA.URL().Value()},
			// Descriptive only. They name the run on the approver's client-bindings
			// page; they authorize nothing.
			"labels": map[string]any{"template": "demo-workflow"},
		}
		if expectedSubject != "" {
			fields["expected_subject"] = expectedSubject
		}
		resp, body := postJSON(t, up, as.summon, runsPath, bearer(harnessJWT), fields)
		require.Equal(t, http.StatusCreated, resp.StatusCode, "create pending run: %v", body)
		runID, _ = body["run_id"].(string)
		approvalURL, _ = body["approval_url"].(string)
		return runID, approvalURL
	}
	createPendingRun := func(prompt, podUID string) (runID, approvalURL string) {
		return createPinnedRun(prompt, podUID, "")
	}

	// pollToken is the real executor shape: the pod-attested sidecar presents ONLY
	// its token — no run_id. The AS resolves the run from the sidecar's own identity
	// (the databroker seal index) and returns run_id as an output.
	pollToken := func(podUID string) (*http.Response, map[string]any) {
		return postJSON(t, up, as.token, tokenPath, bearer(sidecarJWT(podUID)), map[string]any{})
	}

	browser := newBrowsers()
	consentGet := func(email, runID string) (int, string) {
		return browser.consentGet(t, up, as.approve, email, runID)
	}
	approvePost := func(email, code string) (int, string) {
		return browser.approvePost(t, up, as.approve, email, code)
	}

	// --- 1. Create a pending run with a prompt. ---
	const prompt = "Deploy the thing <script>alert(1)</script>"
	runID, approvalURL := createPendingRun(prompt, "pod-uid-1")
	require.NotEmpty(t, runID, "create must return a run_id")
	assert.Contains(t, approvalURL, approvePath+"?run_id=", "response must carry an approval_url")
	assert.Contains(t, approvalURL, as.approve.URL().Value(),
		"the approval link must name the public agentic host — a policy route rewrites Host to the upstream unless preserve_host_header is set, which would mail the approver a loopback URL")

	// --- 1b. Run status: pending, not yet bound, not revoked.
	//
	// The run is already sealed to one executor instance (§12.8), but "bound"
	// reports the run's binding to its APPROVER's IdP session — which does not
	// exist until a human approves — so it is false here. The two are different
	// things: the seal says which workload may act, the binding says whether the
	// run can mint at all. ---
	statusResp, st := getRunStatus(t, up, as.summon, harnessJWT, runID)
	require.Equal(t, http.StatusOK, statusResp.StatusCode, "run status: %v", st)
	assert.Equal(t, runID, st["run_id"])
	assert.Equal(t, "pending_approval", st["state"])
	assert.Equal(t, false, st["bound"], "nobody has approved yet, so there is no binding")
	assert.Equal(t, false, st["revoked"])
	if exp, ok := st["expires_at"].(string); assert.True(t, ok, "expires_at must be a string") {
		_, perr := time.Parse(time.RFC3339, exp)
		assert.NoError(t, perr, "expires_at must be RFC3339")
	}

	// --- 1c. Run status is machine-facing: no credential is refused by the route
	// before the AS sees it, and an unknown run is 404. ---
	statusResp, _ = getRunStatus(t, up, as.summon, "", runID)
	assert.NotEqual(t, http.StatusOK, statusResp.StatusCode, "unauthenticated status must not be served")
	statusResp, _ = getRunStatus(t, up, as.summon, harnessJWT, "00000000-0000-0000-0000-000000000000")
	assert.Equal(t, http.StatusNotFound, statusResp.StatusCode, "unknown run id must be 404")

	// --- 2. Poll before approval: the sealed pod resolves its PENDING run from its
	// own identity and gets 400 authorization_pending. ---
	resp, body := pollToken("pod-uid-1")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "pending run must not issue a token: %v", body)
	assert.Equal(t, "authorization_pending", body["error"])

	// --- 2b. Polling does not create a binding: an unapproved run stays unbound
	// and pending however many times its executor asks. ---
	statusResp, st = getRunStatus(t, up, as.summon, harnessJWT, runID)
	require.Equal(t, http.StatusOK, statusResp.StatusCode)
	assert.Equal(t, false, st["bound"], "polling must not bind a run nobody approved")
	assert.Equal(t, "pending_approval", st["state"], "polling must not change the pending state")

	// --- 3. Instance-pinning by resolution: a different pod (pod-uid-2) has no run
	// sealed to its identity, so it resolves nothing → authorization_pending (never
	// pod-uid-1's run); the sealed pod is pending until approval. ---
	resp, body = pollToken("pod-uid-2")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "a pod with no run sealed to it must be pending")
	assert.Equal(t, "authorization_pending", body["error"])
	resp, body = pollToken("pod-uid-1")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "authorization_pending", body["error"])

	// --- 4. Anonymous consent GET → 302 (login gate). ---
	anonResp, err := up.Get(as.approve,
		upstreams.Path(approvePath),
		upstreams.Query(url.Values{"run_id": {runID}}),
		upstreams.ClientHook(noRedirect),
	)
	require.NoError(t, err)
	anonResp.Body.Close()
	assert.Equal(t, http.StatusFound, anonResp.StatusCode, "anonymous consent GET must redirect to sign-in")

	// --- 5. Authenticated consent GET → 200 with an escaped prompt and a form. ---
	status, page := consentGet("alice@example.com", runID)
	require.Equal(t, http.StatusOK, status, "authenticated consent GET must render the page")
	assert.NotContains(t, page, "<script>", "the prompt must be HTML-escaped, not rendered as markup")
	assert.Contains(t, page, "&lt;script&gt;", "the escaped prompt must appear verbatim")
	assert.Contains(t, page, routeA.URL().Value(), "the consent page must list the granted route")
	assert.Contains(t, page, `name="code"`, "the consent page must carry a hidden approval code")
	assert.Contains(t, page, "alice@example.com", "the consent page must identify the approver")
	assert.Contains(t, page, "kubernetes.io.pod.uid", "the consent page must show the sealed executor (§12.8)")
	assert.Contains(t, page, "pod-uid-1", "the consent page must show the sealed pod uid")

	code := extractApprovalCode(t, page)

	// --- 6. A tampered code is rejected; the run stays pending. ---
	status, _ = approvePost("alice@example.com", "garbage")
	assert.Equal(t, http.StatusBadRequest, status, "a tampered approval code must be rejected")
	resp, body = pollToken("pod-uid-1")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "run must still be pending after a rejected approval")
	assert.Equal(t, "authorization_pending", body["error"])

	// --- 7. Approve as alice → 200. ---
	status, _ = approvePost("alice@example.com", code)
	require.Equal(t, http.StatusOK, status, "approval must succeed")

	// --- 7b. Run status after approval reports approved. ---
	statusResp, st = getRunStatus(t, up, as.summon, harnessJWT, runID)
	require.Equal(t, http.StatusOK, statusResp.StatusCode)
	assert.Equal(t, "approved", st["state"], "run must report approved after approval")
	assert.Equal(t, true, st["bound"])

	// --- 8. Poll after approval → 200 with a run token. The executor bound its run
	// knowing only its own identity, and the resolved run id comes back as an output. ---
	resp, body = pollToken("pod-uid-1")
	require.Equal(t, http.StatusOK, resp.StatusCode, "token issuance after approval: %v", body)
	runToken, _ := body["access_token"].(string)
	require.NotEmpty(t, runToken, "token response must carry an access_token")
	assert.True(t, strings.HasPrefix(runToken, agentic.RunTokenPrefix), "run token must carry the run-token prefix")
	assert.Equal(t, runID, body["run_id"], "the bind returns the resolved run id for addressing callbacks")

	// --- 8c. The minted token is short-lived (rolling): the workload renews it by
	// re-presenting its JWT every poll. Its lifetime is ~1h; there is no fixed run cap. ---
	if ei, ok := body["expires_in"].(float64); assert.True(t, ok, "token response must carry expires_in") {
		assert.Greater(t, ei, float64(600), "a rolling token should still have a meaningful lifetime")
		assert.LessOrEqual(t, ei, float64(3600), "the token must roll at ~1h")
	}

	// --- 9. The run token acts with the approving user's authority. ---
	status, echoBody := getWithToken(t, up, routeA, runToken)
	assert.Equal(t, http.StatusOK, status, "in-scope access should succeed for the alice-approved run")
	assert.Contains(t, echoBody, "ok")
	status, _ = getWithToken(t, up, routeB, runToken)
	assert.Equal(t, http.StatusForbidden, status,
		"a route whose own policy does not admit this agent must deny it — that is what scope is now")

	// --- 9a. Acceptance is per route. routeC's policy is satisfiable by this run,
	// but it declares no bearer_token_format, so the run token is never interpreted
	// there and the request falls through to browser handling. ---
	status, _ = getWithToken(t, up, routeC, runToken)
	assert.NotEqual(t, http.StatusOK, status, "an undeclared route must not honor a run token")

	// --- 9c. Garbage and non-run credentials are denied, never redirected. ---
	status, _ = getWithToken(t, up, routeA, "pom_art_garbage")
	assert.Equal(t, http.StatusForbidden, status, "garbage run token must be denied")
	status, _ = getWithToken(t, up, routeA, harnessJWT)
	assert.NotEqual(t, http.StatusOK, status, "a raw workload JWT must not grant route access")

	// --- 9b. A run token presented alongside a browser session cookie is a
	// confused client: a bearer-token route rejects the combination with 400. Sign
	// alice in on routeA's host first so its jar holds a session cookie; the
	// consent flow no longer leaves one there, since the consent page lives on the
	// agentic host now. ---
	warm, err := up.Get(routeA, upstreams.Path("/echo"), upstreams.AuthenticateAs("alice@example.com"))
	require.NoError(t, err)
	warm.Body.Close()
	cookieBearer, err := up.Get(routeA,
		upstreams.Path("/echo"),
		upstreams.Headers(bearer(runToken)),
		upstreams.ClientHook(noRedirect), // keep the jar, unlike runTokenClient
	)
	require.NoError(t, err)
	cookieBearer.Body.Close()
	assert.Equal(t, http.StatusBadRequest, cookieBearer.StatusCode,
		"a session cookie + run token on a bearer-token route must be rejected as 400")

	// --- 10. The approver's identity drives authority: a run approved by mallory
	// is denied by the alice-only PPL. Both humans now approve on the same agentic
	// host, so consentGet/approvePost give each one its own cookie jar. run2 is
	// sealed to a distinct pod (pod-uid-2), since one pod maps to one run. ---
	run2ID, _ := createPendingRun("Second run", "pod-uid-2")
	status, page = consentGet("mallory@example.com", run2ID)
	require.Equal(t, http.StatusOK, status, "mallory must be able to view the consent page")
	status, _ = approvePost("mallory@example.com", extractApprovalCode(t, page))
	require.Equal(t, http.StatusOK, status, "mallory's approval must succeed")

	resp, body = pollToken("pod-uid-2")
	require.Equal(t, http.StatusOK, resp.StatusCode, "token issuance for the mallory-approved run: %v", body)
	malloryToken, _ := body["access_token"].(string)
	require.NotEmpty(t, malloryToken)
	status, _ = getWithToken(t, up, routeA, malloryToken)
	assert.Equal(t, http.StatusForbidden, status, "a mallory-approved run must fail the alice-only PPL")

	// --- 10a. expected_subject stops that one step earlier. Above, mallory's
	// approval SUCCEEDS and is only caught downstream by PPL — which means a run
	// whose grants happened to suit mallory would have run with her authority off a
	// forwarded link. A run pinned to alice refuses her at the approval itself.
	//
	// This matters most where the workspace outlives the session: a suspended
	// sandbox holds the conversation on a volume whose only access control is
	// application routing, so a fresh approval by the original owner is what keeps a
	// mis-routed revive from handing one person's history to another. ---
	require.NotEmpty(t, alice.ID, "the mock IdP must have assigned alice a subject")
	run3ID, _ := createPinnedRun("Pinned to alice", "pod-uid-3", alice.ID)

	// The consent page is refused outright, so mallory is never handed a working
	// Approve button — and no approval code is minted for her at all.
	status, page = consentGet("mallory@example.com", run3ID)
	assert.Equal(t, http.StatusForbidden, status, "a run pinned to alice must not show mallory a consent page")
	assert.NotContains(t, page, "name=\"code\"", "a refused consent page must not carry a submittable approval code")

	// And the POST is gated independently of the page, so a forwarded code does not
	// help either: alice's own code, submitted by mallory, is refused.
	status, alicePage := consentGet("alice@example.com", run3ID)
	require.Equal(t, http.StatusOK, status, "the pinned approver must still be able to view the consent page")
	aliceCode := extractApprovalCode(t, alicePage)
	status, _ = approvePost("mallory@example.com", aliceCode)
	assert.Equal(t, http.StatusForbidden, status, "mallory must not be able to approve a run pinned to alice, even with a valid code")

	// The run is therefore still unapproved: nothing was activated, so a mis-routed
	// approval cannot start the agent at all.
	resp, body = pollToken("pod-uid-3")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a run whose only approval attempt was refused must still be pending: %v", body)
	assert.Equal(t, "authorization_pending", body["error"], "%v", body)

	// The pinned approver is unaffected: pinning refuses the wrong person, it does
	// not make the run harder to approve for the right one.
	status, _ = approvePost("alice@example.com", aliceCode)
	require.Equal(t, http.StatusOK, status, "the pinned approver's own approval must succeed")
	resp, body = pollToken("pod-uid-3")
	require.Equal(t, http.StatusOK, resp.StatusCode, "token issuance after the pinned approval: %v", body)

	// --- 11. Double approval: re-submitting run-1's (already-consumed) code → 409.
	// A fresh GET would show the already-approved page with no form, so reuse the
	// original code, which is still cryptographically valid but the run is sealed. ---
	status, _ = approvePost("alice@example.com", code)
	assert.Equal(t, http.StatusConflict, status, "a second approval of an already-approved run must conflict")

	// --- 12. Approval binds the run to the approver's centralized IdP session.
	// The run's session record is a bound dependent of that IDPSession, so it can
	// be revoked from the user's own session list. ---
	ctx := env.Context()
	dbClient := env.NewDataBrokerServiceClient()
	run1, err := agentic.GetRun(ctx, dbClient, runID)
	require.NoError(t, err)
	require.NotEmpty(t, run1.GetSub(), "an approved run must record its approver's subject")

	binding, err := idpsessionpb.GetBinding(ctx, dbClient, agentic.SessionID(runID))
	require.NoError(t, err, "approval must create the run's idpsession binding")
	assert.Equal(t, idpsessionpb.BindingProtocol_BINDING_PROTOCOL_AGENTIC, binding.GetProtocol())
	assert.Equal(t, run1.GetSub(), binding.GetIdpSessionId(), "the binding must point at the approver's idp session (keyed by user id)")
	assert.Equal(t, runID, binding.GetDetails()["run_id"])

	// The binding also carries what the run IS, captured at consent. The client
	// bindings page renders from these and nothing else, because the binding
	// outlives the run record's TTL — so a run the user can still revoke must stay
	// nameable after the record backing it is gone.
	assert.Equal(t, "demo-workflow", binding.GetDetails()["label.template"],
		"the approved run's labels must survive on the binding")
	assert.Equal(t, run1.GetPrompt(), binding.GetDetails()["prompt"],
		"the binding must carry the prompt the user actually approved")

	// --- 13. Liveness gate: when the approver's upstream IdP session ends (they
	// sign out / the provider revokes), the run can no longer mint tokens — the
	// agent's work stops. Invalidating alice's IdP session does not affect
	// mallory's run, proving the gate is per-approver. ---
	_, err = idpsessionpb.RevokeIDPSession(ctx, dbClient, run1.GetSub(), "test: approver signed out")
	require.NoError(t, err)

	resp, body = pollToken("pod-uid-1")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "a signed-out approver must stop token issuance: %v", body)
	assert.Equal(t, "access_denied", body["error"])

	// mallory's run (its own pod) is unaffected — her IdP session is still valid.
	resp, body = pollToken("pod-uid-2")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "another approver's live run must keep issuing tokens: %v", body)

	// --- 14. Per-run revocation from the session list: revoking just run-2's
	// binding (what the user's session page does) stops that run at the next poll,
	// without touching the underlying IdP session. ---
	require.NoError(t, idpsessionpb.RevokeBinding(ctx, dbClient, agentic.SessionID(run2ID)))
	resp, body = pollToken("pod-uid-2")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "a run whose binding was revoked must stop issuing tokens: %v", body)
	assert.Equal(t, "access_denied", body["error"])
}
