package agentic

import (
	"context"
	"fmt"
	"html/template"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/config"
	agenticpb "github.com/pomerium/pomerium/internal/agentic/gen"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/mcp"
	"github.com/pomerium/pomerium/internal/opaquetoken"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	idpsessionpb "github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
)

// approvalCodeTTL bounds how long a rendered consent form stays submittable.
const approvalCodeTTL = 10 * time.Minute

// ApproveGet handles GET /agentic/approve?run_id=... It renders the consent page
// for a signed-in user.
//
// The approve route's policy is what requires a session; this handler reads the
// resulting identity from X-Pomerium-Jwt-Assertion, which reaches it only because
// that route sets pass_identity_headers. Without that line the header is stripped
// on the way upstream and every approval 401s here.
func (h *Handler) ApproveGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims, err := getClaimsFromRequest(r)
	if err != nil {
		// The route's policy should guarantee a signed-in user, and
		// pass_identity_headers should guarantee the assertion reaches us. Its
		// absence means one of the two is missing from the route (misconfiguration).
		log.Ctx(ctx).Error().Err(err).Msg("agentic: approve: missing identity assertion; does the approve route set pass_identity_headers?")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	runID := r.URL.Query().Get("run_id")
	if runID == "" {
		http.Error(w, "run_id is required", http.StatusBadRequest)
		return
	}

	run, ok := h.getRunForApproval(w, r, runID)
	if !ok {
		return
	}

	if run.GetRevoked() || run.GetExpiresAt().AsTime().Before(time.Now()) {
		renderPage(ctx, w, http.StatusOK, unapprovablePage, nil)
		return
	}
	if run.GetState() != agenticpb.RunState_RUN_STATE_PENDING {
		renderPage(ctx, w, http.StatusOK, alreadyApprovedPage, nil)
		return
	}
	// Refuse here as well as on POST. The POST check is the control; this one is so
	// somebody holding a forwarded link is told straight away instead of being shown
	// a working Approve button that will refuse them after they click it. It also
	// mints no approval code, so the page cannot be submitted at all.
	if expected := run.GetExpectedSubject(); expected != "" && expected != str(claims["sub"]) {
		log.Ctx(ctx).Info().
			Str("run-id", runID).
			Str("actor", str(claims["sub"])).
			Msg("agentic: approve: consent page requested by someone this run is not pinned to")
		renderPage(ctx, w, http.StatusForbidden, notYourApprovalPage, nil)
		return
	}

	// The code is an unguessable, server-encrypted one-time value bound to this
	// run; carried as a hidden form field it is the CSRF protection
	// (synchronizer-token pattern) — a cross-site attacker cannot read it.
	code, err := opaquetoken.Seal(opaquetoken.TypeAuthorization, run.GetId(), time.Now().Add(approvalCodeTTL), "", h.cipher)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("agentic: approve: failed to mint approval code")
		http.Error(w, "failed to prepare approval", http.StatusInternalServerError)
		return
	}

	// r.Host is the public approve host — and only because the approve route sets
	// preserve_host_header. Every link on this page is built from it.
	servers := h.mcpConsents(ctx, run, str(claims["sub"]), r.Host)
	needsConnect := false
	for _, rc := range servers {
		if rc.NeedsOAuth && !rc.Connected {
			needsConnect = true
			break
		}
	}

	renderPage(ctx, w, http.StatusOK, consentPage, consentPageData{
		UserEmail:    str(claims["email"]),
		UserID:       str(claims["sub"]),
		Prompt:       run.GetPrompt(),
		Labels:       runLabels(run),
		MCPServers:   servers,
		ApprovePath:  ApprovePath(h.prefix),
		NeedsConnect: needsConnect,
		// A failed Connect redirects back here with connect_error set (see the MCP
		// connect handler); surface it so the approver isn't left on a silently
		// reloaded page. html/template escapes it.
		ConnectError: r.URL.Query().Get("connect_error"),
		Executor:     executorClaims(run),
		Code:         code,
	})
}

// ApprovePost handles POST /.pomerium/agentic/approve. It seals a pending run to
// the approving user. First approval wins.
func (h *Handler) ApprovePost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims, err := getClaimsFromRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("agentic: approve: missing identity assertion")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	userID, ok := getUserIDFromClaims(claims)
	if !ok || userID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "code is required", http.StatusBadRequest)
		return
	}
	decoded, err := opaquetoken.Open(opaquetoken.TypeAuthorization, code, h.cipher, "", time.Now())
	if err != nil {
		// Tampered, forged, or expired code.
		http.Error(w, "invalid or expired approval code", http.StatusBadRequest)
		return
	}
	runID := decoded.GetId()

	// The version the run is read at gates the commit below: the pending check
	// here is not enough on its own, because two approvers can both pass it.
	run, runVersion, err := GetRunRecordVersion(ctx, h.db(), runID)
	if status.Code(err) == codes.Unavailable {
		log.Ctx(ctx).Error().Err(err).Msg("agentic: approve: databroker unavailable")
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	} else if err != nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	if run.GetRevoked() || run.GetExpiresAt().AsTime().Before(time.Now()) {
		http.Error(w, "run can no longer be approved", http.StatusForbidden)
		return
	}
	if run.GetState() != agenticpb.RunState_RUN_STATE_PENDING {
		http.Error(w, "run already approved", http.StatusConflict)
		return
	}
	// The run may pin who is allowed to approve it. Without this, an interactive run
	// is approved by whoever opens the URL and passes the route's policy — so a
	// forwarded approval link could be approved by a colleague, and the run would
	// then act with THEIR delegated authority rather than the intended person's.
	//
	// Compared against the subject from the assertion, which is the same string
	// committed as run.Sub below, so what is checked and what is recorded can never
	// disagree. The reason is deliberately not disclosed to the browser: a caller
	// that pinned the wrong subject learns it from the log, while someone holding a
	// forwarded link learns only that they cannot approve it.
	if expected := run.GetExpectedSubject(); expected != "" && expected != userID {
		log.Ctx(ctx).Info().
			Str("run-id", runID).
			Str("actor", userID).
			Str("expected-subject", expected).
			Msg("agentic: approve: refused, this run is pinned to a different approver")
		renderPage(ctx, w, http.StatusForbidden, notYourApprovalPage, nil)
		return
	}

	// Bind the run to the approver's centralized IdP session. The run session is a
	// dependent of that IDPSession (idpsession.NewBoundRecords): the identity
	// manager keeps it fresh and, when the user signs out or the IdP session dies,
	// revokes the binding and deletes the run's session — so the run lives exactly
	// as long as the approver's sign-in, with no per-run refresh token held here.
	client := h.db()

	// The assertion names the approver's session id as `sid`. Load it and confirm
	// it belongs to the same subject we are about to record, so what is checked and
	// what is stored cannot disagree.
	sid, _ := claims["sid"].(string)
	approverSession, err := session.Get(ctx, client, sid)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("run-id", runID).Msg("agentic: approve: failed to load approver session")
		http.Error(w, "could not load your session", http.StatusInternalServerError)
		return
	}
	if approverSession.GetUserId() != userID {
		log.Ctx(ctx).Error().Str("run-id", runID).Str("actor", userID).
			Msg("agentic: approve: assertion subject does not match the loaded session")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	idpSess, err := idpsessionpb.GetValidIDPSession(ctx, client, userID)
	if status.Code(err) == codes.NotFound {
		// No valid centralized IdP session to bind to. It is created at browser
		// login and invalidated at sign-out; either way the approver must sign in
		// again.
		log.Ctx(ctx).Info().Err(err).Str("run-id", runID).Msg("agentic: approve: approver has no valid centralized idp session")
		renderPage(ctx, w, http.StatusForbidden, noIDPSessionPage, nil)
		return
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("run-id", runID).Msg("agentic: approve: failed to load idp session")
		http.Error(w, "could not record approval, please try again", http.StatusServiceUnavailable)
		return
	}

	// Seal to the approving user and CLAIM the run before writing anything else,
	// conditionally on the version it was read at. Whoever commits first owns the
	// approval; a second approver's write is refused and it never touches the
	// winner's records.
	//
	// This is the reverse of the obvious order, and deliberately so. Writing the
	// bound records first would mean a losing approver had already overwritten the
	// winner's session and binding by the time its own run commit was refused,
	// leaving run.Sub from one approver paired with the other's IdP session — the
	// run's lifetime and revocation would follow the wrong person's session. The
	// cost is a window where a run is APPROVED with no session yet: /token refuses
	// to mint for it, and GET /runs/{run_id} reports bound:false, so it is visible
	// rather than silent.
	run.Sub = userID
	run.State = agenticpb.RunState_RUN_STATE_APPROVED
	if err := PutRunIfUnchanged(ctx, client, run, runVersion); err != nil {
		if databroker.IsRecordVersionMismatch(err) {
			log.Ctx(ctx).Info().Str("run-id", runID).Str("actor", userID).
				Msg("agentic: approve: lost the race, the run was already approved")
			renderPage(ctx, w, http.StatusOK, alreadyApprovedPage, nil)
			return
		}
		log.Ctx(ctx).Error().Err(err).Msg("agentic: approve: failed to store run")
		http.Error(w, "failed to store approval", http.StatusInternalServerError)
		return
	}
	runSession := buildRunSession(idpSess, run, time.Now())
	if _, err := client.Put(ctx, &databroker.PutRequest{
		Records: idpsessionpb.NewBoundRecords(
			idpSess.GetId(),
			idpsessionpb.BindingProtocol_BINDING_PROTOCOL_AGENTIC,
			bindingDisplayDetails(run),
			runSession,
		),
	}); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("run-id", runID).Msg("agentic: approve: failed to bind run session")
		http.Error(w, "failed to store approval", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Info().Str("run-id", run.GetId()).Str("approved-by", userID).Msg("agentic: run approved")
	renderPage(ctx, w, http.StatusOK, approvedPage, nil)
}

// getRunForApproval reads a run and maps read failures to HTTP responses,
// distinguishing a transient databroker outage (503, retryable) from a
// genuinely missing run (404). It writes the response and returns ok=false on
// any failure.
// str reads a string out of a claims map, yielding "" for a missing or
// non-string value.
func str(v any) string {
	s, _ := v.(string)
	return s
}

// mcpConsents builds the per-MCP-server rows shown on the consent page. For
// servers that require an upstream OAuth token, it resolves whether the approving
// user (userID) has already connected and, if not, a Connect link — so the
// approver can hydrate the upstream credential before approving. Without it the
// agent, acting with the approver's identity, could not call that server on their
// behalf (the upstream token is keyed by the approver's user id, and the run
// token cannot perform the browser OAuth dance itself).
//
// This list is a disclosure of the capabilities the approval exposes, not a bound
// on what the run token can reach: that is each route's bearer_token_format plus
// policy. A URL that names no configured MCP server route is still shown — the
// approver asked to be told what the agent intends to use.
func (h *Handler) mcpConsents(ctx context.Context, run *agenticpb.Run, userID, approveHost string) []mcpServerConsent {
	urls := run.GetMcpServers()
	rows := make([]mcpServerConsent, 0, len(urls))

	// The Connect affordance only makes sense when the MCP runtime is enabled
	// (the /.pomerium/mcp/connect endpoint is mounted) and we know who is
	// approving (the upstream token is keyed by user id).
	var c *consentResolver
	if userID != "" && h.cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagMCP) {
		servers, _ := mcp.BuildHostInfo(h.cfg)
		c = &consentResolver{
			handler:     h,
			runID:       run.GetId(),
			userID:      userID,
			approveHost: approveHost,
			servers:     servers,
			storage:     mcp.NewStorage(h.client),
		}
	}

	for _, s := range urls {
		row := mcpServerConsent{URL: s}
		if c != nil {
			c.fill(ctx, &row)
		}
		rows = append(rows, row)
	}
	return rows
}

// consentResolver holds what every row of one consent page resolves against: who
// is approving, which run, which host the page is served on, and the MCP server
// index to look each URL up in.
type consentResolver struct {
	handler       *Handler
	runID, userID string
	approveHost   string
	servers       map[string]mcp.ServerHostInfo
	storage       *mcp.Storage
}

// fill marks row as an MCP OAuth server and resolves the approver's connection
// status when row.URL names an MCP server route with an upstream.
//
// The Connect link targets the MCP route's own /.pomerium/mcp/connect — that is
// where the route's connect handler lives — but returns to the consent page on
// the APPROVE host, which is a different host. That cross-host return is legal
// only because the approve route declares `mcp: client: {}`, which registers its
// host in the MCP client map that isValidRedirectURL consults. So the approver
// connects each server and lands back on the page they started from.
func (c *consentResolver) fill(ctx context.Context, row *mcpServerConsent) {
	u, err := url.Parse(row.URL)
	if err != nil {
		return
	}
	info, ok := c.servers[u.Hostname()]
	if !ok || info.UpstreamURL == "" || info.RouteID == "" {
		// Not an MCP server route with an upstream to connect.
		return
	}
	row.NeedsOAuth = true

	// Connected iff the approver already holds a valid (unexpired) upstream token
	// — the same "valid token exists" check the connect handler short-circuits on
	// (internal/mcp/handler_connect.go).
	token, err := c.storage.GetUpstreamMCPToken(ctx, c.userID, info.RouteID, info.UpstreamURL)
	switch {
	case err == nil && token != nil && (token.GetExpiresAt() == nil || token.GetExpiresAt().AsTime().After(time.Now())):
		row.Connected = true
		return
	case err != nil && status.Code(err) != codes.NotFound:
		// A transient lookup failure: offer Connect anyway (it re-checks
		// authoritatively), but record why the shown status may be stale.
		log.Ctx(ctx).Warn().Err(err).Str("run-id", c.runID).Str("route", row.URL).
			Msg("agentic: approve: upstream token lookup failed; offering connect")
	}

	// The Connect endpoint lives on the MCP route's own origin, taken from the
	// CONFIGURED route rather than from what the caller declared. The two are
	// matched by hostname alone, so a run declaring http://srv.example.com:8443
	// matches the configured https://srv.example.com — and building the link from
	// the declaration would then send the approver to a scheme and port nobody
	// configured, where the OAuth flow is unreachable at best and a different
	// service on that host at worst.
	//
	// The return lands back on the approve host, which is where this page is
	// actually served now that the AS sits behind its own routes.
	configured, err := url.Parse(info.URL)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("run-id", c.runID).Str("route", info.URL).
			Msg("agentic: approve: configured MCP route URL is unparseable; not offering connect")
		return
	}
	connect := url.URL{
		Scheme:   configured.Scheme,
		Host:     configured.Host,
		Path:     endpoints.PathPomeriumMCPConnect,
		RawQuery: url.Values{"redirect_url": {c.handler.approveURL(c.approveHost, c.runID)}}.Encode(),
	}
	row.ConnectURL = connect.String()
}

// Keys of the session binding's details map for an agentic run. The producer is
// bindingDisplayDetails; the consumer is the client-bindings page in
// internal/authenticateflow, which is a different package — so the names are
// constants rather than literals repeated on both sides.
const (
	// DetailRunID is the run's id, the stable handle a user can quote in a bug
	// report or match against a log line.
	DetailRunID = "run_id"
	// DetailPrompt is the request the user approved, verbatim. Already bounded at
	// creation by maxPromptBytes; the page truncates it for display and shows the
	// whole thing on hover, so what is stored is the full text.
	DetailPrompt = "prompt"
	// DetailLabelPrefix namespaces the caller's display labels, so a caller
	// cannot collide with a detail key Pomerium sets itself (client-ip,
	// user-agent, mcp_client_id).
	DetailLabelPrefix = "label."
)

// bindingDisplayDetails renders a run's human-facing facts into the details map
// carried by its session binding.
//
// They are captured here, at the moment of consent, rather than looked up from
// the run record when the page renders: the binding lives until it is revoked or
// the approver's IdP session ends, which routinely outlasts the run record's
// databroker TTL. A render-time lookup would therefore come up empty on exactly
// the oldest bindings — the ones a user is most likely to be revoking. Freezing
// the labels is also the truthful thing to show, since they describe what the
// human actually approved.
func bindingDisplayDetails(run *agenticpb.Run) map[string]string {
	details := map[string]string{DetailRunID: run.GetId()}
	if p := strings.TrimSpace(run.GetPrompt()); p != "" {
		details[DetailPrompt] = p
	}
	for k, v := range run.GetLabels() {
		details[DetailLabelPrefix+k] = v
	}
	return details
}

// executorClaims renders the executor the run was sealed to (§12.8) as sorted
// path/value pairs, so the approving user sees the exact instance — service
// account, pod, image digest, whatever was pinned — that will act on their
// behalf. It is generic: whatever claim subset the caller sealed is shown.
func executorClaims(run *agenticpb.Run) []executorClaim {
	flat := identity.NewFlattenedClaimsFromPB(run.GetBoundClaims())
	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]executorClaim, 0, len(keys))
	for _, k := range keys {
		parts := make([]string, len(flat[k]))
		for i, v := range flat[k] {
			parts[i] = fmt.Sprint(v)
		}
		out = append(out, executorClaim{Path: k, Value: strings.Join(parts, ", ")})
	}
	return out
}

func renderPage(ctx context.Context, w http.ResponseWriter, statusCode int, tmpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := tmpl.Execute(w, data); err != nil {
		// Header is already committed; just record it.
		log.Ctx(ctx).Error().Err(err).Msg("agentic: approve: failed to render page")
	}
}

// --- identity assertion helpers ---
//
// Copied from internal/mcp/handler_authorization.go (package-private there).
// The x-pomerium-jwt-assertion header is parsed UNVERIFIED: Pomerium's authorize
// layer sets it after authorization and strips any client-supplied copy, so on a
// login-gated path its presence and contents are trusted. Never rely on it on a
// path that is not login-gated (e.g. /runs, /token).

func getClaimsFromRequest(r *http.Request) (map[string]any, error) {
	h := r.Header.Get(httputil.HeaderPomeriumJWTAssertion)
	if h == "" {
		return nil, fmt.Errorf("missing %s header", httputil.HeaderPomeriumJWTAssertion)
	}

	token, err := jwt.ParseSigned(h)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}
	var m map[string]any
	if err := token.UnsafeClaimsWithoutVerification(&m); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}
	return m, nil
}

func getUserIDFromClaims(claims map[string]any) (string, bool) {
	userID, ok := claims["sub"].(string)
	return userID, ok
}

// --- consent pages ---

var (
	consentPage         = template.Must(template.New("consent").Parse(consentPageHTML))
	approvedPage        = template.Must(template.New("approved").Parse(approvedPageHTML))
	alreadyApprovedPage = template.Must(template.New("already").Parse(alreadyApprovedPageHTML))
	unapprovablePage    = template.Must(template.New("unapprovable").Parse(unapprovablePageHTML))
	noIDPSessionPage    = template.Must(template.New("noidpsession").Parse(noIDPSessionPageHTML))
	notYourApprovalPage = template.Must(template.New("notyours").Parse(notYourApprovalPageHTML))
)

type consentPageData struct {
	UserEmail    string
	UserID       string
	Prompt       string
	Labels       []runLabel
	MCPServers   []mcpServerConsent
	ApprovePath  string
	NeedsConnect bool
	ConnectError string
	Executor     []executorClaim
	Code         string
}

// mcpServerConsent is one MCP server the run was created to use, as rendered on
// the consent page. For servers that require an upstream OAuth token it also
// carries the approving user's connection status and a Connect link.
type mcpServerConsent struct {
	URL string
	// NeedsOAuth is set when the URL names an MCP server route with an upstream
	// that requires the approver to connect (grant an upstream OAuth token).
	NeedsOAuth bool
	// Connected is set when the approver already holds a valid upstream token for
	// the server (only meaningful when NeedsOAuth).
	Connected bool
	// ConnectURL links to the MCP route's own /.pomerium/mcp/connect endpoint and
	// returns to this consent page; set when NeedsOAuth && !Connected.
	ConnectURL string
}

// executorClaim is one sealed executor identity attribute rendered on the
// consent page (§12.8), e.g. {Path: "kubernetes.io.pod.uid", Value: "<uid>"}.
type executorClaim struct {
	Path  string
	Value string
}

// runLabel is one caller-supplied label, as rendered on the consent page. Labels
// are the run's context — which workflow, which channel, which ticket — and are
// the only thing that distinguishes two otherwise identical prompts, so a human
// cannot meaningfully approve without seeing them.
type runLabel struct {
	Key   string
	Value string
}

// runLabels renders a run's labels as sorted key/value pairs, so the order a
// caller happened to send them in does not change the page.
func runLabels(run *agenticpb.Run) []runLabel {
	labels := run.GetLabels()
	out := make([]runLabel, 0, len(labels))
	for _, k := range slices.Sorted(maps.Keys(labels)) {
		out = append(out, runLabel{Key: k, Value: labels[k]})
	}
	return out
}

const pageStyle = `<style>
body{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5;color:#1a1a1a}
h1{font-size:1.4rem}
blockquote{border-left:3px solid #ccc;margin:1rem 0;padding:.5rem 1rem;background:#f6f6f6;white-space:pre-wrap}
.who{color:#555;font-size:.9rem}
button{font-size:1rem;padding:.6rem 1.4rem;background:#2563eb;color:#fff;border:0;border-radius:.4rem;cursor:pointer}
ul{padding-left:1.2rem}
a.connect{display:inline-block;font-size:.8rem;padding:.1rem .55rem;margin-left:.4rem;background:#2563eb;color:#fff;border-radius:.3rem;text-decoration:none}
.ok{color:#15803d;font-size:.85rem;margin-left:.4rem}
.hint{color:#b45309;font-size:.9rem}
.error{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;padding:.6rem 1rem;border-radius:.4rem;margin:1rem 0}
</style>`

// consentPageHTML uses html/template auto-escaping: the prompt is
// attacker-influenced content, so escaping it is security-relevant.
var consentPageHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Approve agentic run</title>` + pageStyle + `</head>
<body>
<h1>Approve agentic run</h1>
{{if .ConnectError}}<p class="error">{{.ConnectError}}</p>{{end}}
<p class="who">Signed in as {{if .UserEmail}}{{.UserEmail}}{{else}}{{.UserID}}{{end}}.</p>
<p>An agent is requesting to act on your behalf:</p>
<blockquote>{{.Prompt}}</blockquote>
{{if .Labels}}<dl>{{range .Labels}}<dt>{{.Key}}</dt><dd>{{.Value}}</dd>{{end}}</dl>{{end}}
{{if .MCPServers}}<p>You are allowing the agent to access these MCP servers on your behalf:</p>
<ul>{{range .MCPServers}}<li>{{.URL}}{{if .NeedsOAuth}}{{if .Connected}} <span class="ok">&#10003; connected</span>{{else}} <a class="connect" href="{{.ConnectURL}}">Connect</a>{{end}}{{end}}</li>{{end}}</ul>
{{if .NeedsConnect}}<p class="hint">Some of these need you to connect an upstream account first. Until you do, the agent won&#39;t be able to use them on your behalf.</p>{{end}}{{end}}
{{if .Executor}}<p>Only this specific agent instance may act — no other workload can use this approval:</p>
<ul>{{range .Executor}}<li>{{.Path}}: {{.Value}}</li>{{end}}</ul>{{end}}
<p>This run stays active for as long as you remain signed in. The agent keeps renewing its access on your behalf while your session is alive, and it stops automatically once you sign out or your session ends. It appears alongside your other sessions, where you can revoke it at any time.</p>
<form method="POST" action="{{.ApprovePath}}">
<input type="hidden" name="code" value="{{.Code}}">
<button type="submit">Approve</button>
</form>
</body></html>`

var approvedPageHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Run approved</title>` + pageStyle + `</head>
<body><h1>Run approved</h1><p>You can close this window.</p></body></html>`

var alreadyApprovedPageHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Already approved</title>` + pageStyle + `</head>
<body><h1>Already approved</h1><p>This run has already been approved.</p></body></html>`

var unapprovablePageHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Cannot approve</title>` + pageStyle + `</head>
<body><h1>Cannot approve</h1><p>This run can no longer be approved.</p></body></html>`

// notYourApprovalPageHTML answers someone who holds an approval link for a run
// pinned to somebody else. It says the request is not theirs to approve without
// naming who it belongs to: the holder of a forwarded link should not learn the
// intended approver's identity from the refusal, and the caller who set the pin
// has the log line.
var notYourApprovalPageHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Not your approval</title>` + pageStyle + `</head>
<body><h1>Not your approval</h1><p>This request is waiting on someone else to approve it, so there is nothing for you to do here. If you were expecting to approve it, ask whoever sent you this link to start a request of your own.</p></body></html>`

var noIDPSessionPageHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Cannot approve</title>` + pageStyle + `</head>
<body><h1>Cannot approve</h1><p>Your sign-in session is no longer active, so it cannot back a long-running agent. Sign in again and retry the approval.</p></body></html>`
