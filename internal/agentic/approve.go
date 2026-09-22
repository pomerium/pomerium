package agentic

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

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
	"github.com/pomerium/pomerium/ui"
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
		h.serveResult(w, r, "warning", "Cannot approve", "This run can no longer be approved.")
		return
	}
	if run.GetState() != agenticpb.RunState_RUN_STATE_PENDING {
		h.serveAlreadyApproved(w, r)
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
		h.serveNotYourApproval(w, r)
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

	h.servePage(w, r, http.StatusOK, pageApprove, "Approve Agentic Run", consentPageData{
		UserEmail:    str(claims["email"]),
		UserID:       str(claims["sub"]),
		Prompt:       run.GetPrompt(),
		Labels:       runLabels(run),
		MCPServers:   servers,
		ApprovePath:  ApprovePath(h.prefix),
		NeedsConnect: needsConnect,
		// A failed Connect redirects back here with connect_error set (see the MCP
		// connect handler); surface it so the approver isn't left on a silently
		// reloaded page. It is carried as JSON page data and rendered as React text,
		// so it cannot become markup.
		ConnectError: r.URL.Query().Get("connect_error"),
		Executor:     executorClaims(run),
		Code:         code,
		// Where the approver lands after approving, and where they can revoke the
		// run afterwards. Told up front, because "you can stop this later" is part
		// of what they are consenting to.
		SessionsURL: h.sessionsURL(ctx, ""),
	}.toJSON())
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
		h.serveNotYourApproval(w, r)
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
	switch {
	case sid == "" || status.Code(err) == codes.NotFound:
		// A session that ended, was revoked, or was swept is an ordinary
		// authentication condition, not a server fault: the assertion can name a
		// sid that no longer resolves. Answer it the way the missing-IdP-session
		// branch below does — sign in again — rather than with a 500 that reads as
		// a Pomerium failure and logs routine expiry as an error.
		log.Ctx(ctx).Info().Err(err).Str("run-id", runID).
			Msg("agentic: approve: approver has no current session")
		h.serveNoIDPSession(w, r)
		return
	case status.Code(err) == codes.Unavailable:
		log.Ctx(ctx).Error().Err(err).Str("run-id", runID).Msg("agentic: approve: databroker unavailable")
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	case err != nil:
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
		h.serveNoIDPSession(w, r)
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
	//
	// A claim that cannot be completed is released again below, so the window is
	// bounded by this request rather than lasting until the run expires.
	pending := proto.Clone(run).(*agenticpb.Run)
	run.Sub = userID
	run.State = agenticpb.RunState_RUN_STATE_APPROVED
	if err := PutRunIfUnchanged(ctx, client, run, runVersion); err != nil {
		if databroker.IsRecordVersionMismatch(err) {
			log.Ctx(ctx).Info().Str("run-id", runID).Str("actor", userID).
				Msg("agentic: approve: lost the race, the run was already approved")
			h.serveAlreadyApproved(w, r)
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
		// Give the claim back. An approved run with nothing bound to it is unusable
		// and unrecoverable: /token refuses to mint for it and a retry is rejected
		// as "run already approved", so the approval would be spent on a failure
		// the approver could otherwise simply retry.
		h.releaseApproval(ctx, client, pending, userID)
		http.Error(w, "failed to store approval", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Info().Str("run-id", run.GetId()).Str("approved-by", userID).Msg("agentic: run approved")
	// Land the approver on their client-bindings page with the run they just
	// approved highlighted, rather than on a dead-end "you can close this window".
	// The run is now something they own and can revoke, so the useful next screen
	// is the one that lets them do it.
	if u := h.sessionsURL(ctx, SessionID(run.GetId())); u != "" {
		http.Redirect(w, r, u, http.StatusSeeOther)
		return
	}
	// No authenticate URL to send them to (a misconfiguration): say the approval
	// worked rather than answering a successful approval with an error.
	h.serveResult(w, r, "success", "Run approved", "You can close this window.")
}

// releaseApproval restores a run this request claimed but could not finish
// binding, so the approver can retry.
//
// Conditional on the version the run is at now, and only while it is still
// claimed by this approver: anything else having touched it means the claim is
// no longer ours to release. Restoring the exact record read before the claim
// avoids having to know which of its fields the claim overwrote.
func (h *Handler) releaseApproval(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	pending *agenticpb.Run,
	userID string,
) {
	runID := pending.GetId()
	current, version, err := GetRunRecordVersion(ctx, client, runID)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("run-id", runID).
			Msg("agentic: approve: could not re-read the run to release the approval")
		return
	}
	if !IsApproved(current) || current.GetSub() != userID {
		return
	}
	if err := PutRunIfUnchanged(ctx, client, pending, version); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("run-id", runID).
			Msg("agentic: approve: could not release the approval; the run must be re-created")
	}
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
		rows = append(rows, mcpServerConsent{URL: s})
	}
	if c == nil {
		return rows
	}
	// Each row costs a databroker lookup and they are independent, so resolve them
	// concurrently — the same thing the routes portal does for its Connected chips
	// (mcp.checkHostsConnectedForUser). Every fill writes only its own row.
	var wg sync.WaitGroup
	for i := range rows {
		wg.Go(func() { c.fill(ctx, &rows[i]) })
	}
	wg.Wait()
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

	// Connected is mcp.IsUpstreamConnected — the same check, and the same
	// semantics, the routes portal renders its Connected chip from. This page used
	// to add an expiry test of its own, which showed a user with a perfectly good
	// connection as disconnected on one page and connected on the other.
	connected, err := mcp.IsUpstreamConnected(ctx, c.storage, c.userID, info.RouteID, info.UpstreamURL)
	if err != nil {
		// A transient lookup failure: offer Connect anyway (it re-checks
		// authoritatively), but record why the shown status may be stale.
		log.Ctx(ctx).Warn().Err(err).Str("run-id", c.runID).Str("route", row.URL).
			Msg("agentic: approve: upstream token lookup failed; offering connect")
	} else if connected {
		row.Connected = true
		return
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

// The React pages this handler serves. pageApprove is the consent form;
// pageApproveResult is the terminal outcome of an approval (approved, already
// approved, no longer approvable). Refusals reuse the shared "Error" page, so
// they look like every other refusal in Pomerium.
const (
	pageApprove       = "AgenticApprove"
	pageApproveResult = "AgenticApproveResult"
)

// sessionsURL is the approver's client-bindings page on the authenticate
// service — where an approved run appears alongside their other sessions and
// can be revoked. The authenticate service owns those records, so the page only
// exists there; the proxy's own /.pomerium/session_binding_info is a redirect to
// it.
//
// highlight names the session binding the page should point at (see
// agentic.SessionID); pass "" for none. An empty return means the deployment has
// no usable authenticate URL, which callers treat as "no link to offer".
func (h *Handler) sessionsURL(ctx context.Context, highlight string) string {
	u, err := h.cfg.Options.GetAuthenticateURL()
	if err != nil || u == nil {
		log.Ctx(ctx).Error().Err(err).Msg("agentic: approve: no authenticate url to link the approver's sessions page to")
		return ""
	}
	out := *u
	out.Path = endpoints.PathPomeriumDashboard + "/" + endpoints.SubPathSessionBindingInfo
	if highlight != "" {
		out.RawQuery = url.Values{"highlight": {highlight}}.Encode()
	}
	return out.String()
}

// servePage renders one of the React pages from the shared UI bundle, with the
// deployment's branding applied the same way every other Pomerium page applies
// it. The status code is written first, as httputil's error page does, because
// ui.ServePage serves the rendered bytes as content.
func (h *Handler) servePage(
	w http.ResponseWriter,
	r *http.Request,
	statusCode int,
	page, title string,
	data map[string]any,
) {
	if data == nil {
		data = map[string]any{}
	}
	httputil.AddBrandingOptionsToMap(data, h.cfg.Options.BrandingOptions)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := ui.ServePage(w, r, page, title, data); err != nil {
		// Header is already committed; just record it.
		log.Ctx(r.Context()).Error().Err(err).Msg("agentic: approve: failed to render page")
	}
}

// serveResult renders a terminal approval outcome. severity is the MUI alert
// severity the page renders it at ("success", "info" or "warning"); title is
// both the browser title and the alert's heading.
func (h *Handler) serveResult(w http.ResponseWriter, r *http.Request, severity, title, message string) {
	h.servePage(w, r, http.StatusOK, pageApproveResult, title, map[string]any{
		"severity": severity,
		"title":    title,
		"message":  message,
	})
}

// serveRefusal renders a refusal through the shared error responder, so an
// approver who cannot proceed sees exactly what every other Pomerium refusal
// renders — request id, branding and the JSON variant included.
func (h *Handler) serveRefusal(w http.ResponseWriter, r *http.Request, statusCode int, description string) {
	e := httputil.NewError(statusCode, errors.New(description)).WithDescription(description)
	e.BrandingOptions = h.cfg.Options.BrandingOptions
	e.ErrorResponse(r.Context(), w, r)
}

func (h *Handler) serveAlreadyApproved(w http.ResponseWriter, r *http.Request) {
	h.serveResult(w, r, "info", "Already approved", "This run has already been approved.")
}

// serveNotYourApproval answers someone who holds an approval link for a run
// pinned to somebody else. It says the request is not theirs to approve without
// naming who it belongs to: the holder of a forwarded link should not learn the
// intended approver's identity from the refusal, and the caller who set the pin
// has the log line.
func (h *Handler) serveNotYourApproval(w http.ResponseWriter, r *http.Request) {
	h.serveRefusal(w, r, http.StatusForbidden,
		"This request is waiting on someone else to approve it, so there is nothing for you to do here. "+
			"If you were expecting to approve it, ask whoever sent you this link to start a request of your own.")
}

func (h *Handler) serveNoIDPSession(w http.ResponseWriter, r *http.Request) {
	h.serveRefusal(w, r, http.StatusForbidden,
		"Your sign-in session is no longer active, so it cannot back a long-running agent. "+
			"Sign in again and retry the approval.")
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

// --- consent page data ---

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
	// SessionsURL links to the approver's client-bindings page, where this run
	// will appear once approved and can be revoked.
	SessionsURL string
}

// toJSON renders the consent page's data as the JSON map handed to the React
// bundle (window.POMERIUM_DATA). The keys are the page's contract with
// ui/src/components/AgenticApprovePage.tsx.
func (d consentPageData) toJSON() map[string]any {
	return map[string]any{
		"userEmail":    d.UserEmail,
		"userId":       d.UserID,
		"prompt":       d.Prompt,
		"labels":       d.Labels,
		"mcpServers":   mcpServerCards(d.MCPServers),
		"approvePath":  d.ApprovePath,
		"needsConnect": d.NeedsConnect,
		"connectError": d.ConnectError,
		"executor":     d.Executor,
		"code":         d.Code,
		"sessionsUrl":  d.SessionsURL,
	}
}

// mcpServerCard is one consent row shaped as the routes portal's Route object,
// so the page can render it with the same MCPRouteCard the routes portal uses
// (ui/src/components/MCPRouteCard.tsx) instead of a second, divergent card.
//
// A run declares MCP servers by URL and nothing else, so the URL is also the
// card's id and title: there is no configured route name to show for a URL that
// names no MCP route at all.
type mcpServerCard struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	From          string `json:"from"`
	MCPNeedsOAuth bool   `json:"mcp_needs_oauth"`
	MCPConnected  bool   `json:"mcp_connected"`
	MCPConnectURL string `json:"mcp_connect_url,omitempty"`
}

func mcpServerCards(rows []mcpServerConsent) []mcpServerCard {
	out := make([]mcpServerCard, 0, len(rows))
	for _, row := range rows {
		out = append(out, mcpServerCard{
			ID:            row.URL,
			Name:          row.URL,
			Type:          "mcp",
			From:          row.URL,
			MCPNeedsOAuth: row.NeedsOAuth,
			MCPConnected:  row.Connected,
			MCPConnectURL: row.ConnectURL,
		})
	}
	return out
}

// mcpServerConsent is one MCP server the run was created to use, as rendered on
// the consent page. For servers that require an upstream OAuth token it also
// carries the approving user's connection status and a Connect link.
type mcpServerConsent struct {
	URL string
	// NeedsOAuth is set when the URL names an MCP server route with an upstream
	// that requires the approver to connect (grant an upstream OAuth token).
	NeedsOAuth bool
	// Connected is set when the approver already holds an upstream token for the
	// server (only meaningful when NeedsOAuth).
	Connected bool
	// ConnectURL links to the MCP route's own /.pomerium/mcp/connect endpoint and
	// returns to this consent page; set when NeedsOAuth && !Connected.
	ConnectURL string
}

// executorClaim is one sealed executor identity attribute rendered on the
// consent page (§12.8), e.g. {Path: "kubernetes.io.pod.uid", Value: "<uid>"}.
type executorClaim struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}

// runLabel is one caller-supplied label, as rendered on the consent page. Labels
// are the run's context — which workflow, which channel, which ticket — and are
// the only thing that distinguishes two otherwise identical prompts, so a human
// cannot meaningfully approve without seeing them.
type runLabel struct {
	Key   string `json:"key"`
	Value string `json:"value"`
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
