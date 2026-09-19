package agentic

import (
	"context"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/oauth21"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	idpsessionpb "github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
)

// DefaultPrefix is where the agentic endpoints are mounted on the AS's own
// listener. Deployments put ordinary routes in front of these paths — a prefix
// route for /agentic/runs and exact-path routes for the other two — and it is
// those routes, not the AS, that decide who may summon, exchange or approve.
const DefaultPrefix = endpoints.PathAgentic

const (
	// defaultRunTTL and maxRunTTL bound the caller-supplied ttl_seconds, which is
	// the APPROVAL window: how long a human has to click. It says nothing about
	// how long an approved run lives — that is the admin's idle timeout.
	defaultRunTTL = time.Hour
	maxRunTTL     = 24 * time.Hour
	// defaultAccessTokenTTL is the rolling lifetime of a minted run token. The
	// workload renews it by re-presenting its workload JWT every poll. This is the
	// clock that carries the security property: a longer-lived run extends no
	// credential, because every credential expires within this window unless the
	// approver's IdP session is still live at the next poll.
	defaultAccessTokenTTL = time.Hour
	// maxRequestBytes bounds a caller-supplied JSON body before it is decoded.
	// Every other bound in this block is checked on the DECODED value, which is
	// too late to matter: an authenticated workload could otherwise make the AS
	// read and allocate a multi-megabyte string before it was rejected. The
	// figure is far above any legitimate request — a 4KiB prompt, 32 server URLs,
	// 32 sealed claims and 16 labels together do not approach it.
	maxRequestBytes = 64 << 10
	// maxPromptBytes bounds the human-readable prompt stored on a run and rendered
	// on the consent page, keeping records and pages bounded.
	maxPromptBytes = 4096
	// maxMCPServers bounds the disclosure list a caller may attach to a run, for
	// the same reason: it is stored on the record and rendered on a page a human
	// has to read.
	maxMCPServers = 32
	// maxLabels, maxLabelKeyBytes and maxLabelValueBytes bound the caller-supplied
	// display labels. Pomerium cannot validate their meaning — that is the point
	// of a generic map — so it validates the only thing it can: that a run record
	// and the page rendering it stay bounded.
	maxLabels          = 16
	maxLabelKeyBytes   = 64
	maxLabelValueBytes = 256
)

// Handler serves the agentic run-identity endpoints. Like mcp.Handler it is
// rebuilt on every config change, so it holds an immutable config snapshot.
type Handler struct {
	prefix      string
	router      *mux.Router
	cfg         *config.Config
	client      databroker.ClientGetter
	cipher      cipher.AEAD
	idpResolver *config.IdentityProviderResolver
}

// db resolves the current databroker client. Resolving per call (rather than
// capturing one) keeps the handler working across outbound-connection reloads,
// matching how mcp.Storage accesses the databroker.
func (h *Handler) db() databroker.DataBrokerServiceClient {
	return h.client.GetDataBrokerServiceClient()
}

// Option configures a Handler.
type Option func(*Handler)

// WithPreviousIdentityProviderResolver hands the rebuilt Handler the resolver of
// the generation it replaces. The resolver is only reused when nothing it is
// built from changed, so this keeps the JWKS caches behind it across
// configuration changes that do not concern identity providers.
func WithPreviousIdentityProviderResolver(previous *config.IdentityProviderResolver) Option {
	return func(h *Handler) {
		h.idpResolver = previous
	}
}

// IdentityProviderResolver returns the resolver this Handler verifies workload
// JWTs with, so the next generation can be built from it.
func (h *Handler) IdentityProviderResolver() *config.IdentityProviderResolver {
	return h.idpResolver
}

// New builds a Handler bound to cfg's shared-key-derived cipher. The databroker
// client is resolved per request from the ClientGetter, so the handler survives
// outbound-connection reloads (the getter is normally the Proxy itself).
func New(
	ctx context.Context,
	prefix string,
	cfg *config.Config,
	client databroker.ClientGetter,
	opts ...Option,
) (*Handler, error) {
	c, err := NewCipher(cfg)
	if err != nil {
		return nil, fmt.Errorf("get cipher: %w", err)
	}

	h := &Handler{
		prefix: prefix,
		cfg:    cfg,
		client: client,
		cipher: c,
	}
	for _, o := range opts {
		o(h)
	}
	// Built here, off the request path, from the previous generation's resolver
	// (nil on the first build). It cannot fail: a provider that could not be built
	// rejects the tokens of its own issuer and reports itself unhealthy.
	h.idpResolver = config.NewIdentityProviderResolverFromConfig(ctx, cfg, h.idpResolver)
	h.router = h.newRouter()
	return h, nil
}

// HandlerFunc returns an http.HandlerFunc serving the agentic endpoints.
func (h *Handler) HandlerFunc() http.HandlerFunc {
	return h.router.ServeHTTP
}

// newRouter builds the endpoint router. It runs once per Handler — the Handler
// itself is rebuilt on every config change — because each mux.Router path
// compiles a regexp, and rebuilding the table per request costs ~50x the
// dispatch it replaces.
func (h *Handler) newRouter() *mux.Router {
	r := mux.NewRouter()
	r.Path(RunsPath(h.prefix)).Methods(http.MethodPost).HandlerFunc(h.CreateRun)
	r.Path(path.Join(RunsPath(h.prefix), "{run_id}")).Methods(http.MethodGet).HandlerFunc(h.GetRun)
	r.Path(TokenPath(h.prefix)).Methods(http.MethodPost).HandlerFunc(h.Token)
	r.Path(ApprovePath(h.prefix)).Methods(http.MethodGet).HandlerFunc(h.ApproveGet)
	r.Path(ApprovePath(h.prefix)).Methods(http.MethodPost).HandlerFunc(h.ApprovePost)
	// Nothing ties a route's prefix to where the AS actually mounts its
	// endpoints, so a typo in a route's `prefix:` produces a request that reaches
	// this handler and matches nothing. Say which server answered and where it
	// serves, instead of a bare 404 that looks like the upstream is missing.
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, fmt.Sprintf(
			"the agentic authorization server does not serve %s; its endpoints are under %s",
			r.URL.Path, h.prefix), http.StatusNotFound)
	})
	return r
}

// The AS's endpoint paths, derived from the prefix it is mounted at. Deployments
// route to them by convention, and every self-link the AS builds goes through the
// same derivation, so a link can never point at where the AS used to live.
func RunsPath(prefix string) string    { return path.Join(prefix, "runs") }
func TokenPath(prefix string) string   { return path.Join(prefix, "token") }
func ApprovePath(prefix string) string { return path.Join(prefix, "approve") }

// approveURL is the consent page for runID on host. Both the approval link handed
// to a caller and the Connect round trip's return build it here, so they cannot
// drift apart.
func (h *Handler) approveURL(host, runID string) string {
	u := url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     ApprovePath(h.prefix),
		RawQuery: url.Values{"run_id": {runID}}.Encode(),
	}
	return u.String()
}

// --- request/response bodies ---

type createRunRequest struct {
	// MCPServers lists the MCP server URLs this run was created to use. It is a
	// disclosure, not a grant: it tells the approver which upstream accounts the
	// agent will act with on their behalf, and drives the Connect affordance for
	// the ones needing hydration. What the run token may actually reach is decided
	// per route, by that route's bearer_token_format and policy.
	MCPServers []string `json:"mcp_servers"`
	// TTLSeconds is the approval window: how long the human has to click. It is
	// clamped to (0, maxRunTTL]. It does not bound an approved run, which lives
	// as long as it keeps being renewed within the deployment's idle timeout.
	TTLSeconds int64  `json:"ttl_seconds"`
	Prompt     string `json:"prompt"`
	// Executor is the attested identity subset of the one specific executor
	// instance this run is pinned to (§12.8), e.g.
	// {"kubernetes.io.serviceaccount.name":"sandbox-agent",
	//  "kubernetes.io.pod.uid":"<uid>"}. The keys are flattened claim paths that
	// must match, key-for-key, what the executor's own verified token carries.
	// The run is sealed to this executor at creation; at bind, the presenting
	// workload's verified claims must reproduce the seal.
	Executor map[string]string `json:"executor"`
	// ExpectedSubject pins WHO may approve this run: at approval the approver's
	// own subject must equal it. Optional; empty leaves the run approvable by
	// anyone who can open the approval URL and passes the approve route's policy.
	//
	// The value is the raw upstream IdP subject, NOT an email — see
	// AgenticRun.expected_subject.
	ExpectedSubject string `json:"expected_subject"`
	// Labels are descriptive attributes naming what this run is — the workflow
	// definition it instantiates, the channel it was summoned from. They are
	// shown to the approving human on their client-bindings page, so the run is
	// something they can recognise rather than a bare uuid.
	//
	// Like MCPServers they grant nothing. Pomerium privileges no key and
	// interprets no value; it bounds their size and stores them.
	Labels map[string]string `json:"labels"`
}

type createRunResponse struct {
	RunID     string `json:"run_id"`
	ExpiresAt string `json:"expires_at"`
	// ApprovalURL is where a human goes to approve this run. Always present:
	// every run needs an approval.
	ApprovalURL string `json:"approval_url"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	// RunID is the id of the run the token was minted for. It lets a workload that
	// bound without knowing a run_id (resolved from its own identity via the seal)
	// learn its run id as an output of a successful bind — e.g. to address a
	// result callback — without ever having to input one or ask the summoner.
	RunID string `json:"run_id"`
}

type runStatusResponse struct {
	RunID string `json:"run_id"`
	State string `json:"state"`
	// Bound reports whether this run currently has a live binding to its
	// approver's IdP session — that is, whether it can still mint a token.
	//
	// It is NOT derived from the run's bound_claims: those are the executor seal
	// written at creation, so they are set on every properly sealed run including
	// one nobody has approved, and they stay set after the binding is revoked.
	// Reporting them as "bound" told an orchestrator that a pending or revoked run
	// was live.
	Bound     bool   `json:"bound"`
	Revoked   bool   `json:"revoked"`
	ExpiresAt string `json:"expires_at"`
	// ApproverSubject is the IdP subject of the human who approved this run, once
	// one has. Empty while a run is pending, and empty for a non-interactive run —
	// whose Sub is the creating workload, not a person.
	//
	// It exists so a caller can pin a LATER run to the same human via
	// expected_subject. A caller that summons agents on behalf of chat users
	// typically knows them only by a chat identity, so the first approval is the
	// only place it can learn the IdP subject that expected_subject requires. It is
	// disclosed only to the workload that created the run, over its own
	// authenticated status poll.
	ApproverSubject string `json:"approver_subject,omitempty"`
}

// CreateRun handles POST /agentic/runs. The caller authenticates with its
// workload JWT — and reaches this handler at all only because the summon route's
// policy admitted it. The run is created PENDING: there is no shape in which a
// run exists without a human having approved it, which is what makes act.*
// claims on a route mean "a person consented to this".
func (h *Handler) CreateRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	workloadID, _, err := h.verifyWorkloadJWT(r)
	if err != nil {
		log.Ctx(ctx).Info().Err(err).Msg("agentic: create run: workload jwt verification failed")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req createRunRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			http.Error(w, fmt.Sprintf("request body must be at most %d bytes", maxRequestBytes),
				http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// mcp_servers is optional — a run that needs no upstream account is perfectly
	// ordinary — but each entry has to be a real URL, since the consent page
	// resolves it against the configured MCP server routes.
	if len(req.MCPServers) > maxMCPServers {
		http.Error(w, fmt.Sprintf("mcp_servers must have at most %d entries", maxMCPServers), http.StatusBadRequest)
		return
	}
	for _, s := range req.MCPServers {
		if _, err := urlutil.ParseAndValidateURL(s); err != nil {
			http.Error(w, "mcp_servers entries must be absolute URLs", http.StatusBadRequest)
			return
		}
	}

	if len(req.Prompt) > maxPromptBytes {
		http.Error(w, fmt.Sprintf("prompt must be at most %d bytes", maxPromptBytes), http.StatusBadRequest)
		return
	}

	if err := validateLabels(req.Labels); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Seal the run to one specific executor instance at creation (§12.8). The
	// caller launches the executor first, reads its attested identity, and pins
	// the run to it here — so knowing a run_id never lets an unexpected workload
	// bind. executor is required; a run with no seal could never bind.
	sealed, err := sealExecutor(req.Executor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ttl := clampRunTTL(req.TTLSeconds)

	now := time.Now()
	run := &oauth21proto.AgenticRun{
		Id:          uuid.NewString(),
		McpServers:  req.MCPServers,
		CreatedAt:   timestamppb.New(now),
		ExpiresAt:   timestamppb.New(now.Add(ttl)),
		BoundClaims: sealed.ToPB(),
		// Who asked for this run. Service-account scoped, because that is what a
		// projected token's sub is: a restarted summoner must still be able to read
		// the runs its predecessor created.
		CreatedBy: workloadID,
		// sub stays empty until a human approves; only then does the run have an
		// identity to act as.
		State:  oauth21proto.AgenticRunState_AGENTIC_RUN_STATE_PENDING,
		Prompt: req.Prompt,
		// Optionally pin who that approving user must be, so a forwarded approval
		// URL cannot be approved by the wrong person.
		ExpectedSubject: req.ExpectedSubject,
		// The databroker index derived from bound_claims: the token bind resolves
		// this run by it — the presenting workload token reproduces the same value
		// from its own claims via sealIndexKey, so a pod finds its run from its
		// identity alone (no run_id). Empty for a non-k8s executor.
		BoundClaimsIndex: sealIndexKey(sealed),
		// Descriptive only — they name the run for the human who has to decide
		// whether to keep it, and authorize nothing.
		Labels: req.Labels,
	}
	// PutRun writes run.BoundClaimsIndex, which the databroker indexes (see
	// setupRequiredIndex): a workload then binds with its token alone (no run_id)
	// and the /token handler resolves this run by re-deriving the same value from
	// the presenting claims. The index is a lookup only; the seal-match at bind
	// remains authoritative.
	if err := PutRun(ctx, h.db(), run); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("agentic: create run: failed to store run")
		http.Error(w, "failed to store run", http.StatusInternalServerError)
		return
	}

	if run.GetBoundClaimsIndex() == "" {
		// The seal carries none of the claims a presenting executor could be
		// recognised by, so nothing will ever bind this run: a human may approve it
		// and then watch an agent poll forever. Say so at creation, where the caller
		// can still be fixed, rather than leaving it to be diagnosed from silence.
		log.Ctx(ctx).Warn().Str("run-id", run.Id).Str("created-by", workloadID).
			Msg("agentic: create run: the sealed executor cannot be resolved from a presenting token; no workload will be able to bind this run")
	}

	log.Ctx(ctx).Info().Str("run-id", run.Id).Str("created-by", workloadID).Msg("agentic: created run")
	writeJSON(w, http.StatusCreated, createRunResponse{
		RunID:     run.Id,
		ExpiresAt: run.ExpiresAt.AsTime().Format(time.RFC3339),
		// Built from the request Host, which is the public host only because the
		// summon route sets preserve_host_header: a policy route otherwise rewrites
		// it to the upstream address and this link would name the AS's loopback
		// listener.
		ApprovalURL: h.approveURL(r.Host, run.Id),
	})
}

// GetRun handles GET /agentic/runs/{run_id}, returning a run's status so an
// orchestrator can render it without inferring state from token polls. It is
// machine-facing (workload-JWT authenticated) and shares the summon route, so
// the route's policy already decides which workloads may ask at all.
//
// A run's status is disclosed only to the workload that created it. Both are
// service-account-level identities, so a restarted summoner still reads its
// predecessor's runs; a different service account admitted by the same route
// does not. Runs created before created_by existed answer 404 to everyone.
func (h *Handler) GetRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	workloadID, _, err := h.verifyWorkloadJWT(r)
	if err != nil {
		log.Ctx(ctx).Info().Err(err).Msg("agentic: get run: workload jwt verification failed")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	run, ok := h.getRunForApproval(w, r, mux.Vars(r)["run_id"])
	if !ok {
		return
	}
	if run.GetCreatedBy() == "" || run.GetCreatedBy() != workloadID {
		// Answered as "not found" rather than "forbidden": whether a run id exists
		// is not something to confirm to a workload that did not create it.
		log.Ctx(ctx).Info().Str("run-id", run.GetId()).Str("caller", workloadID).
			Msg("agentic: get run: refused, the caller did not create this run")
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}

	bound, err := h.runIsBound(ctx, run)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("run-id", run.GetId()).
			Msg("agentic: get run: failed to read the run's binding")
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, http.StatusOK, runStatusResponse{
		RunID:     run.GetId(),
		State:     stateString(run),
		Bound:     bound,
		Revoked:   run.GetRevoked(),
		ExpiresAt: run.GetExpiresAt().AsTime().Format(time.RFC3339),
		// Set only once a human has approved, so a half-written record never
		// reports somebody as an approver.
		ApproverSubject: approverSubject(run),
	})
}

// approverSubject returns the IdP subject of the human who approved a run, or ""
// when nobody has yet.
// stateString renders a run's approval state for the status endpoint.
// Token handles POST /agentic/token. The executor authenticates with its
// workload JWT and its verified claims must reproduce the executor instance the
// run was sealed to (§12.8 instance-pinning) — a run_id alone never entitles a
// workload to bind. An opaque run token is then minted.
//
// Which identity providers may attest a binding executor is the exchange route's
// business, not this handler's: a token from a provider the route does not list
// is rejected before authorize even evaluates policy, so it never arrives here.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	subject, rawClaims, err := h.verifyWorkloadJWT(r)
	if err != nil {
		log.Ctx(ctx).Info().Err(err).Msg("agentic: token: workload jwt verification failed")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	claims := identity.Claims(rawClaims).Flatten()

	// The workload proves who it is; the run it belongs to is resolved from its own
	// attested claims via the databroker seal index. run_id is never an input — a
	// pod never needs to know one (it is returned as an output of a successful bind).
	boundClaimsIndex := sealIndexKey(claims)
	if boundClaimsIndex == "" {
		// A token carrying none of the fixed k8s executor claims can't be sealed to
		// any run. Report pending so a misconfigured caller polls harmlessly.
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.AuthorizationPending)
		return
	}
	run, err := QueryRunByBoundClaimsIndex(ctx, h.db(), boundClaimsIndex)
	if status.Code(err) == codes.Unavailable {
		// Distinguish a transient databroker outage (retryable) from "no such run".
		log.Ctx(ctx).Error().Err(err).Msg("agentic: token: databroker unavailable")
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("agentic: token: seal index query failed")
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if run == nil {
		// No run is sealed to this executor. Three quite different situations look
		// identical from here — the summoner has not created it yet (the launch
		// race), this workload is not an expected executor at all, or the run aged
		// out of storage under its TTL and took a live conversation with it — so
		// name the last one rather than leaving an operator to guess from silence.
		log.Ctx(ctx).Info().Str("subject", subject).
			Msg("agentic: token: no run is sealed to this executor (never created, not an expected executor, or the run record has aged out)")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.AuthorizationPending)
		return
	}
	if run.GetRevoked() || run.GetExpiresAt().AsTime().Before(time.Now()) {
		http.Error(w, "run is revoked or expired", http.StatusForbidden)
		return
	}

	// Instance-pinning (§12.8): the run was sealed to one specific executor
	// instance at creation. The presenting workload's verified claims, projected
	// onto the sealed keys, must reproduce the sealed claims — knowing a run_id is
	// never enough, and a different instance (even under the same service account)
	// is refused. This is a read-only match check; the seal is written only at
	// create, so binding is order-independent and needs no write here.
	if len(run.GetBoundClaims()) == 0 {
		// Defensive: executor is required at create, so a run always carries a
		// seal. No sealed claims means an unpinned run, which can never bind.
		log.Ctx(ctx).Info().Str("run-id", run.GetId()).Msg("agentic: token: run is not pinned to an executor")
		oauth21.ErrorResponse(w, http.StatusForbidden, oauth21.AccessDenied)
		return
	}
	presented := projectClaims(claims, run.GetBoundClaims())
	sealed := identity.NewFlattenedClaimsFromPB(run.GetBoundClaims())
	if canonicalClaims(presented) != canonicalClaims(sealed) {
		log.Ctx(ctx).Info().Str("run-id", run.GetId()).Str("subject", subject).
			Msg("agentic: token: executor does not match the pinned instance")
		oauth21.ErrorResponse(w, http.StatusForbidden, oauth21.AccessDenied)
		return
	}

	// Binding and approval are order-independent by design: a pod may bind a run
	// before the human approves. Token issuance, however, requires an approval.
	if !IsApproved(run) {
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.AuthorizationPending)
		return
	}

	now := time.Now()
	client := h.db()

	// A run lives only as long as the approving user's centralized IdP session.
	// The background identity manager owns upstream refresh and marks the
	// IDPSession invalid when the user signs out or the provider revokes it; we
	// only read that state here. This is a synchronous mirror of what the manager's
	// reconciler does anyway (revoke the run's binding, delete its session), so
	// issuance stops at the next poll even before the reconcile lands.
	idpSess, err := idpsessionpb.GetValidIDPSession(ctx, client, run.GetSub())
	if status.Code(err) == codes.NotFound {
		log.Ctx(ctx).Info().Err(err).Str("run-id", run.Id).Msg("agentic: token: approver has no valid centralized idp session; refusing to mint")
		oauth21.ErrorResponse(w, http.StatusForbidden, oauth21.AccessDenied)
		return
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("run-id", run.Id).Msg("agentic: token: idp session lookup failed")
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	// The run's own binding (created at approval) is the per-run kill switch: a
	// user can revoke it from their session page, and the manager revokes it when
	// the IDPSession dies. Missing means it was revoked and swept past its grace
	// period, or approval never created it — either way the run may not mint. The
	// binding is never (re-)created here; recreating it would resurrect a revoked
	// run.
	_, err = idpsessionpb.GetActiveBinding(ctx, client, SessionID(run.Id))
	if status.Code(err) == codes.NotFound {
		log.Ctx(ctx).Info().Err(err).Str("run-id", run.Id).Msg("agentic: token: no active binding for this run; it was revoked or never approved")
		oauth21.ErrorResponse(w, http.StatusForbidden, oauth21.AccessDenied)
		return
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("run-id", run.Id).Msg("agentic: token: binding lookup failed")
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	// Two clocks, deliberately different. The token is short-lived and rolling:
	// the workload renews it every poll by re-presenting its JWT, and that is what
	// carries the security property — a token stops working within the hour unless
	// the liveness gate above passed again.
	//
	// The run record's clock is the idle timeout, and it is pushed forward on
	// EVERY mint, unconditionally. A guard here ("only extend if this token
	// outlives the run") would leave an actively-polling run untouched for hours,
	// so its storage TTL would age from a write that happened long ago and the
	// record could be swept out from under a live conversation.
	tokenExpiry := now.Add(defaultAccessTokenTTL)
	run.ExpiresAt = timestamppb.New(now.Add(h.cfg.Options.GetAgenticRunIdleTimeout()))
	if err := PutRun(ctx, client, run); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("run-id", run.Id).Msg("agentic: token: failed to extend run expiry")
		http.Error(w, "failed to update run", http.StatusInternalServerError)
		return
	}

	// Refresh the run's session record, created at approval as a bound dependent of
	// the approver's IDPSession. Only the session is written — never the binding,
	// which would resurrect a revoked run. It is written AFTER the run record so
	// the version embedded in the token gives authorize read-your-writes on the
	// session; the earlier run write sits at a lower (already visible) version.
	s := buildRunSession(idpSess, run, now)
	res, err := session.Put(ctx, client, s)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("agentic: token: failed to store session")
		http.Error(w, "failed to store session", http.StatusInternalServerError)
		return
	}
	version := res.GetRecord().GetVersion()

	tok, err := MintRunToken(h.cipher, run.Id, tokenExpiry, version)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("agentic: token: failed to mint run token")
		http.Error(w, "failed to mint token", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Info().Str("run-id", run.Id).Str("subject", subject).Msg("agentic: issued run token")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: tok,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Until(tokenExpiry).Seconds()),
		RunID:       run.Id,
	})
}

// verifyWorkloadJWT authenticates the caller by its external-issuer JWT and
// returns the "<provider>/<sub>" identity together with the verified claims.
//
// This is the second verification of the same token: the route in front of the
// AS already verified it against that route's identity_providers allowlist and
// minted a session from it. Keeping this one means the handler's own behaviour
// does not depend on how it is mounted, and the cost is a cached JWKS check —
// but note that WHICH providers are acceptable is the route's decision, not
// this resolver's, which accepts any configured provider.
func (h *Handler) verifyWorkloadJWT(r *http.Request) (workloadID string, claims map[string]any, err error) {
	auth := r.Header.Get(httputil.HeaderAuthorization)
	const bearer = "Bearer "
	if len(auth) < len(bearer) || !strings.EqualFold(auth[:len(bearer)], bearer) {
		return "", nil, fmt.Errorf("missing bearer token")
	}
	rawJWT := auth[len(bearer):]

	if h.idpResolver == nil {
		return "", nil, fmt.Errorf("no identity providers configured")
	}

	res, err := h.idpResolver.Verify(r.Context(), rawJWT)
	if err != nil {
		return "", nil, fmt.Errorf("verify workload jwt: %w", err)
	}
	sub, _ := res.Claims["sub"].(string)
	if sub == "" {
		return "", nil, fmt.Errorf("workload jwt missing sub claim")
	}
	return res.ProviderName + "/" + sub, res.Claims, nil
}

// validateLabels bounds the caller-supplied display labels. It deliberately
// checks size and nothing else: labels carry no meaning to Pomerium, so there is
// no value to validate, only a record and a rendered page to keep finite. An
// empty key is rejected because it would render as a blank caption line the user
// cannot interpret.
func validateLabels(labels map[string]string) error {
	if len(labels) > maxLabels {
		return fmt.Errorf("labels must have at most %d entries", maxLabels)
	}
	for k, v := range labels {
		if k == "" {
			return fmt.Errorf("label keys must be non-empty")
		}
		if len(k) > maxLabelKeyBytes {
			return fmt.Errorf("label keys must be at most %d bytes", maxLabelKeyBytes)
		}
		if len(v) > maxLabelValueBytes {
			return fmt.Errorf("label values must be at most %d bytes", maxLabelValueBytes)
		}
	}
	return nil
}

// clampRunTTL converts a client-supplied ttl_seconds to a run duration, bounded
// to (0, maxRunTTL]. It clamps in seconds space *before* converting to a
// Duration: time.Duration(ttlSeconds)*time.Second overflows int64 for very
// large inputs (wrapping negative), which would otherwise slip past a
// post-multiply cap and produce an already-expired run.
func clampRunTTL(ttlSeconds int64) time.Duration {
	if ttlSeconds <= 0 {
		return defaultRunTTL
	}
	if maxSeconds := int64(maxRunTTL / time.Second); ttlSeconds > maxSeconds {
		return maxRunTTL
	}
	return time.Duration(ttlSeconds) * time.Second
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) getRunForApproval(w http.ResponseWriter, r *http.Request, runID string) (*oauth21proto.AgenticRun, bool) {
	ctx := r.Context()
	run, err := GetRun(ctx, h.db(), runID)
	if status.Code(err) == codes.Unavailable {
		log.Ctx(ctx).Error().Err(err).Msg("agentic: approve: databroker unavailable")
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return nil, false
	} else if err != nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return nil, false
	}
	return run, true
}

// decodeJSONBody decodes a caller-supplied JSON body, refusing to read more than
// maxRequestBytes of it. MaxBytesReader also closes the connection's read side
// once the limit is hit, so an oversized body is not drained on the way to the
// error.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	return json.NewDecoder(r.Body).Decode(dst)
}

// runIsBound reports whether run still has an active binding to its approver's
// IdP session, which is what decides whether it can mint. A run that was never
// approved has no binding; a revoked one has a binding in the REVOKED state,
// which GetActiveBinding reports as absent. Only a transient databroker failure
// is an error — "no binding" is an ordinary answer.
func (h *Handler) runIsBound(ctx context.Context, run *oauth21proto.AgenticRun) (bool, error) {
	if !IsApproved(run) {
		return false, nil
	}
	_, err := idpsessionpb.GetActiveBinding(ctx, h.db(), SessionID(run.GetId()))
	switch status.Code(err) {
	case codes.OK:
		return true, nil
	case codes.NotFound:
		return false, nil
	default:
		return false, err
	}
}
