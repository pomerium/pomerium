// Package idpsession holds one canonical record per user's upstream
// identity-provider session, replacing the per-consumer upstream refresh
// previously implemented in internal/mcp.
//
// The record owns and rotates the upstream refresh token. Browser sessions and
// MCP sessions are projections repopulated from it. EnsureLive refreshes against
// the IdP at most once per user per token lifetime (or per debounce window), so
// N consumers cause at most one IdP call rather than N.
//
// Two properties hold by design:
//
//   - A refresh token is never presented twice. Every presentation is preceded
//     by a committed write-ahead intent, and an intent whose outcome never
//     committed is resolved without contacting the IdP. Re-presenting a
//     possibly-consumed token trips reuse detection, which revokes the user's
//     whole grant family.
//
//     This holds unconditionally except on the probe path, which rests on one
//     assumption: that a family observed not to rotate never starts rotating.
//     Providers that rotate conditionally — Okta and Auth0 rotate a refresh
//     token as it nears its own expiry rather than on every grant — void it, so
//     a lost outcome coinciding with the onset of rotation can make the probe
//     present a token the provider has already consumed. Every other path holds
//     without that assumption.
//
//   - Death is recorded as state, not as an absent record. A dead record cannot
//     be resurrected by a consumer re-seeding its stale copy. Only Supersede
//     revives it, and only the login flow calls Supersede, because a login is
//     the one event that produces a token no consumer could have been holding
//     since before the record died.
//
// Both properties hold only while the token family has a single presenter. That
// is what the identity manager refreshing through this store buys: browser
// sessions, MCP sessions and anything else read the same canonical record
// instead of each rotating their own copy of the same grant.
//
// Every age this package measures — how long an intent has stood, how recently a
// refresh succeeded, how long since the last failure — is bounded by the
// databroker's own timestamp for the record, so no replica can date a write into
// the future and stretch what every other replica sees. Replicas therefore need
// to agree with the databroker, not with each other, and only to within much
// less than settleDelay. A replica whose clock runs behind still ages records
// early, which is the residual exposure.
//
// That budget protects retirement unconditionally: settling early under strict
// rotation can only retire a record, never present a token. The probe path is
// different — early settle there produces a presentation, so its safety under
// skew rests on the same never-starts-rotating assumption the probe itself
// depends on.
package idpsession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/oauth21"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

const (
	// recordIDPrefix keeps upstream idp-session ids disjoint from every other
	// databroker namespace (sessions, users, mcp records).
	recordIDPrefix = "idpsess-"

	// DefaultMinRefreshInterval floors how often a single user's upstream session
	// is refreshed against the IdP, regardless of how many browser sessions or MCP
	// clients poll for liveness in that window.
	DefaultMinRefreshInterval = 2 * time.Minute

	// refreshGrace is how long before expiry a stored token is treated as stale,
	// so a projection never receives an almost-expired token.
	refreshGrace = time.Minute

	// refreshTimeout bounds the IdP call.
	refreshTimeout = 30 * time.Second

	// commitTimeout bounds the write of an attempt's outcome, including its
	// retry-while-suppressed loop. That write runs detached from the caller's
	// context (see attempt), so it needs its own deadline.
	commitTimeout = 30 * time.Second

	// settleDelay is how long an intent whose outcome never committed is treated
	// as possibly still in flight, and so how long before it may be resolved.
	//
	// The age it is compared against starts when the intent was committed, which
	// is earlier than when the IdP call starts: the flight has to acknowledge,
	// and resolving the provider can itself perform OIDC discovery. Measuring
	// only the refresh timeout from the intent would therefore be unsound, so the
	// budget counts a whole detached attempt at its ceiling, refreshTimeout plus
	// two commitTimeouts, which is 90 seconds. That leaves 90 seconds of margin
	// for dispatch and for clock skew against the databroker, two orders above
	// what a synchronized fleet drifts.
	settleDelay = 3 * time.Minute

	// callerBudget caps the wall time EnsureLive makes its caller wait, across
	// every phase: polling, flights, and the IdP call the caller may itself have
	// started. The gateway in front of these routes has a 15 second default
	// timeout, and a caller must answer with its own 503 and a Retry-After well
	// before that, or the gateway replaces it with a bodyless 504 the client
	// cannot act on.
	//
	// Exceeding it does not abandon work: once an intent is committed the attempt
	// owes the cluster an outcome and runs to completion on a detached context.
	// The caller simply stops waiting for it, and whoever asks next adopts what
	// it committed.
	callerBudget = 8 * time.Second

	// maxEnsureAttempts bounds how many times the wait-and-retry loop asks, so a
	// caller cannot spin inside callerBudget.
	maxEnsureAttempts = 8

	// maxWriteAttempts bounds the retry loop for writes. It is separate from
	// maxEnsureAttempts because a write retries only while another flight holds
	// the key, which clears in about the time one flight takes, and because the
	// attempt commit runs under commitTimeout.
	maxWriteAttempts = 5

	// Waiting callers poll with jitter so they do not re-converge on the same
	// instant after every wait.
	pollMinDelay = 250 * time.Millisecond
	pollMaxDelay = 1250 * time.Millisecond

	// DefaultRetryAfter is the retry hint given for a first failure, and
	// maxRetryAfter caps the backoff applied to repeated ones. A record whose
	// refreshes keep failing for a reason no retry can fix, such as a rotated
	// client secret, must not have every consumer of that user asking again
	// every few seconds forever.
	DefaultRetryAfter = 5 * time.Second
	maxRetryAfter     = 5 * time.Minute

	// recordTTL is how long the databroker keeps a canonical record after its
	// last write. Every refresh outcome rewrites the record, so a record in
	// active use never expires. A DEAD record is never written again, so it is
	// deleted one TTL after it died. A LIVE record that nothing has used for
	// this long is deleted too, which makes the TTL an idle-grant expiry.
	//
	// Deleting a tombstone reopens the window in which a consumer holding a
	// stale copy can seed the pair again, so the TTL is much longer than any
	// session lifetime.
	recordTTL = 90 * 24 * time.Hour

	// optionsRetryInterval throttles re-publishing the record TTL after a
	// failure, so a databroker that keeps refusing it does not add a round trip
	// to every write.
	optionsRetryInterval = time.Minute
)

// Reasons a record is DEAD. They are labels for logs and telemetry: every one of
// them is terminal, and no held copy of the token revives the record. Only
// Supersede does.
const (
	// deadReasonIDPRevoked: the IdP refused a validated record's token.
	deadReasonIDPRevoked = "idp_revoked"
	// deadReasonSeedInvalid: the first validation of a seeded token failed, so
	// the seed was stale. This is not the same as the user signing out.
	deadReasonSeedInvalid = "seed_invalid"
	// deadReasonUnknownOutcome: an attempt's outcome never committed and the
	// settle window passed. On a provider observed to rotate the token may
	// already be consumed, so the record is retired without presenting it again.
	deadReasonUnknownOutcome = "unknown_outcome"
	// deadReasonPomeriumSignout: the user signed out of Pomerium.
	deadReasonPomeriumSignout = "pomerium_signout"
)

var (
	// ErrNoUpstreamSession means no canonical record exists yet for (user, idp).
	// A caller that holds a valid upstream refresh token should Register it and retry.
	ErrNoUpstreamSession = errors.New("idpsession: no upstream session for user")

	// ErrUpstreamSessionDead means the upstream session is permanently over: the
	// user signed out, the token was revoked, or an attempt's outcome was lost
	// and the token can no longer be safely presented. No seed resurrects it;
	// only a fresh login through Supersede does.
	ErrUpstreamSessionDead = errors.New("idpsession: upstream session is no longer valid")

	// ErrRefreshUnavailable means the upstream session could not be proven live
	// right now: the IdP failed transiently, another attempt holds the intent, or
	// presentation is debounced. It is not a sign-out, so callers keep the
	// session and retry later. Every error wrapping it reports Temporary() ==
	// true, which is what pkg/identity/manager checks.
	ErrRefreshUnavailable = errors.New("idpsession: upstream refresh unavailable")

	// ErrRecordUndecodable means the stored record could not be parsed. Retrying
	// cannot fix it, so it is neither transient nor a statement about the grant,
	// and callers should report it as a server error.
	ErrRecordUndecodable = errors.New("idpsession: record could not be decoded")

	errRecordNotFound = errors.New("idpsession: record not found")
)

// IsTemporary reports whether err means "retry later" rather than "the grant is
// over". True when err wraps context.DeadlineExceeded or context.Canceled (an
// outcome that was never learned), or when err implements
// interface{ Temporary() bool } reporting true.
func IsTemporary(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var t interface{ Temporary() bool }
	return errors.As(err, &t) && t.Temporary()
}

// transientError is the "retry later" outcome. It reports Temporary() so that
// callers checking only for net-style temporariness, such as
// pkg/identity/manager, treat it as transient without importing this package.
type transientError struct {
	reason     string
	cause      error
	retryAfter time.Duration
}

func (e *transientError) Error() string {
	if e.cause == nil {
		return fmt.Sprintf("%s: %s", ErrRefreshUnavailable, e.reason)
	}
	return fmt.Sprintf("%s: %s: %s", ErrRefreshUnavailable, e.reason, e.cause)
}

func (e *transientError) Temporary() bool { return true }

// RetryAfter is how long the caller should wait before asking again.
func (e *transientError) RetryAfter() time.Duration { return e.retryAfter }

func (e *transientError) Unwrap() []error {
	if e.cause == nil {
		return []error{ErrRefreshUnavailable}
	}
	return []error{ErrRefreshUnavailable, e.cause}
}

// transient builds the "retry later" error with the hint the caller should
// honor. Pass DefaultRetryAfter where no record is in hand to size it from.
func transient(reason string, cause error, retryAfter time.Duration) error {
	return &transientError{reason: reason, cause: cause, retryAfter: retryAfter}
}

// RetryAfter reports how long a caller should wait before retrying err, and
// whether err carried a hint at all.
func RetryAfter(err error) (time.Duration, bool) {
	var t interface{ RetryAfter() time.Duration }
	if errors.As(err, &t) {
		return t.RetryAfter(), true
	}
	return 0, false
}

// retryAfterFor backs off with the number of consecutive failures, so a record
// that keeps failing for a reason retrying cannot fix stops being asked about
// every few seconds by every consumer of that user.
func retryAfterFor(consecutiveFailures uint32) time.Duration {
	if consecutiveFailures <= 1 {
		return DefaultRetryAfter
	}
	// Capped before the shift as well as after, so a long-failing record cannot
	// shift a duration past its own width.
	if consecutiveFailures > 20 {
		return maxRetryAfter
	}
	return min(DefaultRetryAfter<<(consecutiveFailures-1), maxRetryAfter)
}

// storeError classifies a failure from the databroker or the transport.
//
// databrokerutil reports failures as typed gRPC status errors (Aborted,
// Unavailable, DeadlineExceeded, Internal, FailedPrecondition), none of which
// implement Temporary(). Returned unchanged they read as "the grant is over",
// which would tell an MCP client to discard a refresh token that is still
// valid, so they are wrapped as transient here instead.
//
// Errors that describe the grant rather than the infrastructure pass through
// unchanged, as does errRecordNotFound, which callers match on.
func storeError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errRecordNotFound) ||
		errors.Is(err, ErrUpstreamSessionDead) ||
		errors.Is(err, ErrNoUpstreamSession) ||
		errors.Is(err, ErrRefreshUnavailable) ||
		errors.Is(err, ErrRecordUndecodable) {
		return err
	}
	return transient("databroker operation failed", err, DefaultRetryAfter)
}

// DeadSessionError carries why the upstream session died. It matches
// ErrUpstreamSessionDead under errors.Is, so callers that only need to know the
// session is over can ignore the reason.
type DeadSessionError struct {
	Reason string
}

func (e *DeadSessionError) Error() string {
	return fmt.Sprintf("%s (%s)", ErrUpstreamSessionDead, e.Reason)
}

func (e *DeadSessionError) Unwrap() error { return ErrUpstreamSessionDead }

func deadError(reason string) error { return &DeadSessionError{Reason: reason} }

// DeadReason returns the reason a session died, or "" if err is not a death.
func DeadReason(err error) string {
	var de *DeadSessionError
	if errors.As(err, &de) {
		return de.Reason
	}
	return ""
}

// LiveOption adjusts a single EnsureLive call.
type LiveOption func(*liveOptions)

type liveOptions struct {
	requireFresh bool
}

// RequireFresh serves the stored token only when liveness was checked within the
// debounce window, and otherwise goes to the IdP even though the stored token has
// not expired.
//
// Without it a caller is served any unexpired token, so a user whose upstream
// session was revoked keeps being treated as signed in until that token expires.
// Callers that mint something long-lived from the answer, such as the MCP token
// endpoint minting a session, use this to bound that window to the debounce
// interval. It costs at most one extra IdP call per user per window, shared by
// every caller.
//
// The identity manager also uses it, because a scheduled refresh means something
// hit its expiry and the record's ID token only advances when the store actually
// presents. That fixes the rescheduling loop for providers that return id_token
// on refresh. For a provider that never returns one, with
// refresh_session_at_id_token_expiration enabled, the session's ID token cannot
// advance at all and the manager still reschedules — bounded to one presentation
// per debounce window rather than one per cool-off period, which is a large
// reduction but not a fix.
func RequireFresh() LiveOption {
	return func(o *liveOptions) { o.requireFresh = true }
}

// AuthenticatorGetter resolves the identity provider that can refresh a given idp id.
type AuthenticatorGetter func(ctx context.Context, idpID string) (identity.Authenticator, error)

// CacheAuthenticators memoizes an AuthenticatorGetter per idp id.
//
// Resolving a provider is not cheap: it scans the policy set and can perform
// OIDC discovery. More importantly the provider owns the oauth2 config, which
// remembers which client-authentication style the token endpoint accepted, and a
// provider built fresh for every refresh throws that away — leaving x/oauth2 to
// re-probe and silently re-POST a failed refresh with the other style, which
// presents a one-time-use token twice. See pkg/identity/oidc.Provider.
//
// A failed resolution is memoized like a successful one: the entry's Once has
// run, so every later call for that idp id gets the same error until the getter
// is rebuilt. That is the intended behavior here, because the causes are
// configuration ones that a retry does not fix, and the alternative is every
// consumer of that provider re-running discovery on every liveness question. A
// configuration change rebuilds the getter and clears it.
//
// The cache lives as long as the getter, so callers rebuild it when the
// configuration changes.
func CacheAuthenticators(get AuthenticatorGetter) AuthenticatorGetter {
	type entry struct {
		once sync.Once
		auth identity.Authenticator
		err  error
	}
	var mu sync.Mutex
	byIDP := map[string]*entry{}
	return func(ctx context.Context, idpID string) (identity.Authenticator, error) {
		// The map lock is held only long enough to find the entry. Resolving a
		// provider can perform OIDC discovery over the network, so it happens
		// under that entry's own Once: two callers for one provider wait for each
		// other, callers for different providers do not.
		mu.Lock()
		e, ok := byIDP[idpID]
		if !ok {
			e = new(entry)
			byIDP[idpID] = e
		}
		mu.Unlock()

		e.once.Do(func() { e.auth, e.err = get(ctx, idpID) })
		return e.auth, e.err
	}
}

// Live is the snapshot a projection uses to repopulate its own session from the
// canonical upstream session.
//
// Use IDTokenUpdate rather than reading the two fields: an empty RawIDToken on
// its own means nothing was observed, not that the assertion was withdrawn, and
// a consumer that gets that rule wrong fails silently in one of two directions.
type Live struct {
	Token      *oauth2.Token
	RawIDToken string
	// RawIDTokenCleared distinguishes a provider that withdrew the ID token from
	// one that simply never sent a new one. Most providers omit id_token on
	// refresh, and a consumer that assigned RawIDToken unconditionally would blank
	// the one its session was created with. A consumer repopulating an existing
	// session assigns only when RawIDToken is non-empty or this is set.
	RawIDTokenCleared bool
	Claims            identity.FlattenedClaims
}

// IDTokenUpdate reports the ID token a consumer repopulating an existing session
// should store, and whether the provider said anything about it at all. A false
// second return means leave what the session already has: most providers omit
// id_token on refresh, and blanking on every refresh would break the route
// ID-token headers, sign-out's id_token_hint, and refreshing at ID-token expiry.
func (l *Live) IDTokenUpdate() (string, bool) {
	return l.RawIDToken, l.RawIDToken != "" || l.RawIDTokenCleared
}

// Store owns the canonical UpstreamIdPSession per (user, idp) and debounces IdP
// refreshes so N consumers cause at most one refresh per window.
type Store struct {
	client             databroker.DataBrokerServiceClient
	getAuthenticator   AuthenticatorGetter
	minRefreshInterval time.Duration
	now                func() time.Time
	optionsSet         atomic.Bool
	optionsRetryAt     atomic.Pointer[time.Time]
}

// Option configures a Store.
type Option func(*Store)

// WithMinRefreshInterval overrides DefaultMinRefreshInterval.
func WithMinRefreshInterval(d time.Duration) Option {
	return func(s *Store) { s.minRefreshInterval = d }
}

// WithNow overrides the clock (tests only).
func WithNow(f func() time.Time) Option {
	return func(s *Store) { s.now = f }
}

// New builds a Store. getAuthenticator may be nil for a store used only to
// Register, Supersede or Revoke, since those paths never contact the IdP; the
// login flow constructs one that way on purpose, so it cannot refresh.
func New(client databroker.DataBrokerServiceClient, getAuthenticator AuthenticatorGetter, opts ...Option) *Store {
	s := &Store{
		client:             client,
		getAuthenticator:   getAuthenticator,
		minRefreshInterval: DefaultMinRefreshInterval,
		now:                time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// recordTypeURL is the databroker type of the canonical record, computed once
// rather than per read and write.
var recordTypeURL = protoutil.GetTypeURL(new(oauth21proto.UpstreamIdPSession))

// RecordID derives the deterministic databroker id of the canonical record for a
// (user, idp) pair, so exactly one record exists per pair no matter which
// consumer writes it.
func RecordID(userID, idpID string) string {
	key := databroker.CompositeRecordID(map[string]any{"user_id": userID, "idp_id": idpID})
	sum := sha256.Sum256([]byte(key))
	return recordIDPrefix + hex.EncodeToString(sum[:])
}

// Register seeds the canonical upstream session for (user, idp) from a copy of
// the refresh token some component holds, such as a session record during
// migration or an MCP refresh-token record. It writes only when no record
// exists: a component bootstrapping from its own, possibly stale, copy must
// never replace a token the store has since rotated.
//
// Seeding over a DEAD record is refused. The caller's copy belongs to the same
// grant that died, so accepting it would resurrect a dead session and present a
// token the IdP may already treat as stolen. Only a genuinely fresh grant
// revives such a record, and that arrives through Supersede.
//
// refreshed_at and expires_at are left zero, so the next EnsureLive validates
// the token against the IdP before any projection is repopulated from it.
func (s *Store) Register(ctx context.Context, userID, idpID, upstreamRefreshToken string) error {
	if userID == "" {
		return fmt.Errorf("idpsession: register requires a user id")
	}
	if upstreamRefreshToken == "" {
		return fmt.Errorf("idpsession: register requires an upstream refresh token")
	}
	id := RecordID(userID, idpID)
	return s.do(ctx, id, func(tx databrokerutil.TX) error {
		rec, err := txGet(ctx, tx, id)
		switch {
		case errors.Is(err, errRecordNotFound):
			return txPut(ctx, tx, record{UpstreamIdPSession: &oauth21proto.UpstreamIdPSession{
				Id:                   id,
				UserId:               userID,
				IdpId:                idpID,
				UpstreamRefreshToken: upstreamRefreshToken,
				State:                oauth21proto.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_LIVE,
			}})
		case err != nil:
			return err
		case isDead(rec):
			return deadError(rec.GetDeadReason())
		default:
			return nil // a canonical record exists; it owns the token now
		}
	})
}

// Supersede installs a refresh token that came from a genuinely fresh grant, an
// interactive login's auth-code exchange, and therefore outranks whatever the
// record holds, including a tombstone. It is the only way a dead record comes
// back, which is why the login flow is its only caller.
//
// rawIDToken is the ID token that arrived with the same exchange. Seeding it
// here means projections have one from the moment of login, rather than
// whenever the first refresh that carries one happens to land.
//
// It is safe to run twice against its own committed effect, which Store.do
// requires: a flight whose acknowledgement is lost is retried, and a second
// unconditional write would clear an intent committed in between. That holds for
// a repeated call as well as a repeated flight, so a caller may retry it.
//
// It starts a new epoch: the old token family is abandoned rather than
// continued, so generation restarts at zero and everything learned about the
// previous family, its rotation behavior and failure counters, is re-learned
// rather than inherited.
//
// refreshed_at and expires_at are left zero, so the next EnsureLive validates
// the new token against the IdP before any projection is repopulated from it.
func (s *Store) Supersede(ctx context.Context, userID, idpID, upstreamRefreshToken, rawIDToken string) error {
	if userID == "" {
		return fmt.Errorf("idpsession: supersede requires a user id")
	}
	if upstreamRefreshToken == "" {
		return fmt.Errorf("idpsession: supersede requires an upstream refresh token")
	}
	id := RecordID(userID, idpID)

	// The epoch this call is installing, fixed by whichever run of the callback
	// computes it first. It is the idempotency key: see the retry check below.
	var target uint64

	return s.do(ctx, id, func(tx databrokerutil.TX) error {
		prev, err := txGet(ctx, tx, id)
		switch {
		case errors.Is(err, errRecordNotFound):
		case errors.Is(err, ErrRecordUndecodable):
			// Nothing can be learned from bytes that do not parse, and every read
			// path refuses them, so without this the pair would stay unusable
			// until the record's TTL. A fresh grant is exactly what may replace
			// it, and prev's epoch is unreadable, so the new epoch starts over.
			log.Ctx(ctx).Error().Err(err).Str("record-id", id).
				Msg("idpsession: replacing an unreadable upstream session record")
			prev = record{}
		case err != nil:
			return err
		}

		// Already installed. This is the idempotency the callers can actually rely
		// on: the epoch target below only survives inside one Store.do call. A
		// caller that retries Supersede itself, as the login flow does when a
		// write times out, arrives with a fresh target and would otherwise write
		// again, clearing an intent committed in between and authorizing a second
		// presentation of this very token. Comparing what is stored costs one
		// field and holds however many layers retry.
		if !isDead(prev) && prev.GetUpstreamRefreshToken() == upstreamRefreshToken {
			return nil
		}

		if target == 0 {
			target = prev.GetEpoch() + 1
		} else if prev.GetEpoch() >= target {
			// This callback already ran and committed; only its acknowledgement
			// was lost. Writing again would undo whatever has happened since —
			// in particular an intent committed by a caller that is at the IdP
			// right now with this very token, whose removal would authorize a
			// second presentation of it.
			//
			// This guards one call's retry, not two calls racing. A flight that
			// loses the race is suppressed and never runs this callback at all,
			// so a second login recomputes its target from the record the first
			// one left and installs its own token: concurrent logins serialize
			// through the flight and the last one wins, which is what a user who
			// signed in twice should get.
			return nil
		}

		if isDead(prev) {
			log.Ctx(ctx).Info().
				Str("record-id", id).
				Str("user-id", userID).
				Str("idp-id", idpID).
				Str("previous-dead-reason", prev.GetDeadReason()).
				Uint64("epoch", target).
				Msg("idpsession: a fresh grant revived a retired upstream session")
		}

		// A fresh record rather than an edited one: generation, rotation_observed
		// and the failure counters all describe the family being abandoned.
		return txPut(ctx, tx, record{UpstreamIdPSession: &oauth21proto.UpstreamIdPSession{
			Id:                   id,
			UserId:               userID,
			IdpId:                idpID,
			UpstreamRefreshToken: upstreamRefreshToken,
			RawIdToken:           rawIDToken,
			State:                oauth21proto.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_LIVE,
			Epoch:                target,
		}})
	})
}

// Revoke ends the canonical upstream session for (user, idp) so every projection
// stops treating the user as signed in. Death is written as state rather than by
// deleting the record, because an absent record reads as "never seen" and lets
// every consumer re-seed its own stale copy, replaying a consumed token.
//
// Nothing calls this yet: the sign-out flow is not wired on this branch.
//
// Revoking a pair with no record writes nothing, so callers cannot mint records
// for pairs the store has never seen.
func (s *Store) Revoke(ctx context.Context, userID, idpID string) error {
	id := RecordID(userID, idpID)
	// Reported after the flight, not inside it: a flight whose acknowledgement is
	// lost runs its callback again, and a retirement counted or logged per
	// attempt would report one event several times.
	var retired record
	err := s.do(ctx, id, func(tx databrokerutil.TX) error {
		rec, err := txGet(ctx, tx, id)
		if errors.Is(err, errRecordNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		if isDead(rec) {
			return nil
		}
		markDead(rec, deadReasonPomeriumSignout, s.now())
		retired = rec
		return txPut(ctx, tx, rec)
	})
	if err == nil && retired.UpstreamIdPSession != nil {
		s.recordRetired(ctx, retired, deadReasonPomeriumSignout,
			"idpsession: the upstream session was revoked")
	}
	return err
}

// IsDeadHint reports whether the canonical record for (user, idp) is a
// tombstone, from a plain read and without contacting the IdP. It is a hint, not
// a verdict: EnsureLive deliberately confirms this answer through a flight
// before acting on it, because a follower can still be serving a tombstone a
// login has since superseded.
//
// It answers a question a caller can act on before doing work that a dead record
// would waste, such as issuing an authorization code whose tokens the next
// refresh would refuse. It deliberately does not confirm through a flight: the
// cost of a stale "not dead" here is the work the caller was going to do anyway,
// and a caller acting on "dead" must offer the user a way to sign in rather than
// end anything.
func (s *Store) IsDeadHint(ctx context.Context, userID, idpID string) (bool, error) {
	rec, err := s.get(ctx, RecordID(userID, idpID))
	if err != nil {
		return false, err
	}
	return isDead(rec), nil
}

// EnsureLive checks that the user's upstream IdP session is still alive and
// returns a Live snapshot. The refresh token is presented to the IdP at most
// once cluster-wide per refresh window: concurrent callers on any replica
// observe the committed intent of the one attempt and adopt its outcome.
func (s *Store) EnsureLive(ctx context.Context, userID, idpID string, opts ...LiveOption) (*Live, error) {
	var opt liveOptions
	for _, o := range opts {
		o(&opt)
	}

	// Everything below runs under the caller's budget. Work that must finish
	// regardless is detached from it inside begin.
	budgetCtx, cancel := context.WithTimeout(ctx, callerBudget)
	defer cancel()

	id := RecordID(userID, idpID)
	rec, err := s.get(budgetCtx, id)
	if errors.Is(err, errRecordNotFound) {
		return nil, ErrNoUpstreamSession
	} else if err != nil {
		return nil, err
	}

	waiting := "no refresh attempt could be started"
	retryAfter := DefaultRetryAfter
	for attempt := range maxEnsureAttempts {
		// Judge the record this caller already read. Waiting for someone else's
		// attempt must not cost a transaction and the key's lock on every pass,
		// for every consumer of this user.
		out := s.decide(rec, opt)
		// A flight is opened for two reasons. One is that the decision needs a
		// write. The other is that the decision is "dead": telling a client its
		// grant is over makes it discard a token only a new login can replace, so
		// that verdict is never taken from a plain read, where a follower can
		// still be serving a tombstone that has since been superseded. Either
		// way the flight re-reads and re-decides through the leader, so the read
		// above is only a hint.
		if out.kind == outcomeDead || out.kind.needsWrite() {
			out, err = s.begin(ctx, budgetCtx, id, opt)
			if err != nil {
				return nil, err
			}
			if out.kind == outcomeTimedOut {
				// The attempt is still running detached and will commit its
				// outcome. Stop holding the request open for it.
				s.recordBudgetSpent(ctx, id, "the refresh attempt it started runs on")
				return nil, transient("refresh still in progress", nil, retryAfter)
			}
		}

		switch out.kind {
		case outcomeAbsent:
			// The record vanished (legacy delete or GC). Since death is stored as
			// state, absence is not death, so a holder of a valid token may seed.
			return nil, ErrNoUpstreamSession
		case outcomeDead:
			return nil, deadError(out.rec.GetDeadReason())
		case outcomeLive:
			if !out.presented {
				// Answered from the record, whether this caller read it, adopted
				// what a flight committed, or was suppressed by one. Counting only
				// the first would miss exactly the callers the shared record
				// exists to spare, which are the ones contention produces most of.
				metrics.RecordIdpSessionServedFromRecord(ctx)
			}
			// Answer from the committed snapshot rather than re-reading, because a
			// clustered follower can lag the leader's commit.
			return liveFromRecord(out.rec), nil
		case outcomeDebounced:
			// Debounce only gates presentation; it says nothing about whether the
			// stored token is still valid. Returning an expired one here would
			// make the caller running the flight and the callers it suppresses
			// disagree, which livelocks.
			return nil, transient("refresh debounced", nil, retryAfterFor(out.rec.GetConsecutiveFailures()))
		case outcomeTransient:
			return nil, transient("refresh failed", out.err, retryAfterFor(out.rec.GetConsecutiveFailures()))
		case outcomeInflight:
			waiting = "refresh attempt in flight elsewhere"
			retryAfter = retryAfterFor(out.rec.GetConsecutiveFailures())
		case outcomeContended:
			waiting = "another writer resolved the record first"
			retryAfter = retryAfterFor(out.rec.GetConsecutiveFailures())
		default:
			// outcomeInvalid, or a decision that should not escape decide. Refuse
			// rather than let the zero value be read as one of the cases above.
			return nil, fmt.Errorf("idpsession: internal error: unassigned refresh outcome %d", out.kind)
		}
		if attempt == maxEnsureAttempts-1 {
			break
		}
		if err := s.wait(budgetCtx); err != nil {
			if ctx.Err() != nil {
				return nil, storeError(context.Cause(ctx))
			}
			break // the caller's budget is spent
		}
		// Re-read for the next pass, so the decision above is made against what
		// the holder of the intent has committed since.
		rec, err = s.get(budgetCtx, id)
		if errors.Is(err, errRecordNotFound) {
			return nil, ErrNoUpstreamSession
		} else if err != nil {
			if ctx.Err() == nil && budgetCtx.Err() != nil {
				break // the caller's budget is spent
			}
			return nil, err
		}
	}
	s.recordBudgetSpent(ctx, id, waiting)
	return nil, transient(waiting, nil, retryAfter)
}

// recordBudgetSpent reports a caller that ran out of budget, whether it was
// waiting on its own attempt or on someone else's. Counting only the former
// would under-report by the contention factor, which is the opposite of what
// this measures.
func (s *Store) recordBudgetSpent(ctx context.Context, id, why string) {
	metrics.RecordIdpSessionCallerBudgetTimeout(ctx)
	log.Ctx(ctx).Info().Str("record-id", id).Str("waiting-on", why).
		Msg("idpsession: caller stopped waiting for the upstream session")
}

// begin runs the claim and, when the claim authorizes one, the presentation that
// follows it. Both run on a context detached from the caller: once an intent may
// be committed, an outcome has to be committed too, or the record is left holding
// an intent nobody owns.
//
// The caller waits for that work only until its budget runs out. Past it the
// work continues and outcomeTimedOut is reported, so the request can be answered
// with a retryable error instead of being held until the gateway gives up. The
// next caller reads whatever was committed.
func (s *Store) begin(parent, budgetCtx context.Context, id string, opt liveOptions) (outcome, error) {
	type beginResult struct {
		out outcome
		err error
	}
	// Detached, but not open-ended: every call this work makes, including the
	// ones with no deadline of their own, has to terminate. This envelope covers
	// the claim and the IdP call. The commit of the outcome deliberately sits
	// outside it and adds its own commitTimeout, so the ceiling for one detached
	// attempt is refreshTimeout + 2*commitTimeout, or 90 seconds. settleDelay is
	// sized against that.
	work, stop := context.WithTimeout(context.WithoutCancel(parent), refreshTimeout+commitTimeout)
	done := make(chan beginResult, 1)
	go func() {
		defer stop()
		out, err := s.claim(work, id, opt)
		if err == nil && out.kind == outcomeClaimed {
			out, err = s.attempt(work, id, out)
		}
		done <- beginResult{out, err}
	}()

	select {
	case r := <-done:
		return r.out, r.err
	case <-budgetCtx.Done():
		if parent.Err() != nil {
			return outcome{}, storeError(context.Cause(parent))
		}
		return outcome{kind: outcomeTimedOut}, nil
	}
}

// --- outcomes ---------------------------------------------------------------

type outcomeKind int

const (
	// outcomeInvalid is the zero value, so a missing assignment is not mistaken
	// for a real decision, in particular not for "absent", which would let a
	// caller re-seed its own stale copy.
	_ outcomeKind = iota

	// decisions: what a record calls for. decide produces most of these; absent
	// comes from a flight finding no record, and dead and live are also produced
	// after a write.
	outcomeAbsent   // no record
	outcomeDead     // record is a durable tombstone
	outcomeLive     // a usable token is available
	outcomeInflight // another caller's intent may still be answered
	outcomeDebounced
	outcomeClaim       // this caller should write an intent and present the token
	outcomeResolveDead // a settled intent must be retired without presenting

	// results: only produced after a write or an IdP call.
	outcomeClaimed   // this caller's intent is committed and owns the IdP call
	outcomeTransient // retry later
	outcomeContended // another writer got there first; re-evaluate from scratch
	outcomeTimedOut  // still running detached; the caller stopped waiting
)

// needsWrite reports whether acting on this decision requires a transaction, so
// the two places that route decisions to one agree by construction.
func (k outcomeKind) needsWrite() bool {
	switch k {
	case outcomeClaim, outcomeResolveDead:
		return true
	}
	return false
}

// recordRetired reports a canonical record being retired. Every one of these
// ends every session and MCP client of that user until the user signs in again,
// so it is both counted and logged with what an operator needs to act on.
func (s *Store) recordRetired(ctx context.Context, rec record, reason, msg string) {
	metrics.RecordIdpSessionRecordRetired(ctx, reason)
	log.Ctx(ctx).Warn().
		Str("record-id", rec.GetId()).
		Str("user-id", rec.GetUserId()).
		Str("idp-id", rec.GetIdpId()).
		Str("dead-reason", reason).
		Uint64("generation", rec.GetGeneration()).
		Msg(msg)
}

type outcome struct {
	kind  outcomeKind
	rec   record
	probe bool // this attempt re-presents the token after a settled intent
	// presented records that this outcome cost an IdP call, so the exits can
	// tell an answer the record supplied from one the provider did.
	presented bool
	err       error
}

// decide is the single acceptance predicate. The caller running the flight and
// every caller it suppresses evaluate it on the same record and must reach the
// same conclusion; disagreement between them livelocks.
//
// It is parameterized by the caller through opt, so two callers asking different
// questions can reach different conclusions about one record. That is safe
// because the disagreement is never about whether to write: a caller asking for
// freshness that finds a record another caller accepted simply spends a poll
// slot and asks again.
func (s *Store) decide(rec record, opt liveOptions) outcome {
	if isDead(rec) {
		return outcome{kind: outcomeDead, rec: rec}
	}
	if s.usable(rec, opt) {
		return outcome{kind: outcomeLive, rec: rec}
	}
	if rec.GetRefreshAttemptId() != "" {
		if s.now().Before(writeAnchor(rec, rec.GetRefreshStartedAt()).Add(settleDelay)) {
			return outcome{kind: outcomeInflight, rec: rec}
		}
		if canRePresent(rec) {
			// A completed refresh returned the same refresh token, so presenting
			// it again is idempotent and can recover the record.
			return outcome{kind: outcomeClaim, probe: true, rec: rec}
		}
		// Either the provider is known to rotate, or nothing has ever been
		// observed about it. In both cases the abandoned attempt may already have
		// consumed the stored token, so re-presenting it would be a replay, which
		// revokes the whole family on reuse-detecting IdPs, and the rotated
		// successor is unrecoverable anyway. Retire the record instead.
		return outcome{kind: outcomeResolveDead, rec: rec}
	}
	if s.debounceHoldsBack(rec) {
		return outcome{kind: outcomeDebounced, rec: rec}
	}
	return outcome{kind: outcomeClaim, rec: rec}
}

// debounceHoldsBack reports whether the window is still holding back another
// presentation of a token whose fate is not established.
//
// Two cases are exempt, and they are disjoint by construction: one requires no
// failures since the last success, the other requires at least one failure. A
// record that has just refreshed successfully may present the successor at
// expiry, and a record that has failed is paced by the escalating retry hint
// instead of the flat window.
func (s *Store) debounceHoldsBack(rec record) bool {
	return s.debounced(rec) && !holdsRefreshedSuccessor(rec) && !s.failureBackoffElapsed(rec)
}

// holdsRefreshedSuccessor reports whether the stored refresh token is one a
// completed refresh produced, rather than the token that refresh presented. When
// it is, presenting it at expiry is ordinary behavior even inside the debounce
// window: at-most-once is a rule about a token, not about a window.
//
// Debouncing that case would make a provider whose access tokens are shorter
// than the window unusable for most of every window, with the record expired and
// every caller refused.
func holdsRefreshedSuccessor(rec record) bool {
	return rec.GetGeneration() > 0 &&
		rec.GetConsecutiveFailures() == 0 &&
		rec.GetUpstreamAccessToken() != ""
}

// failureBackoffElapsed reports whether enough time has passed since the last
// failed attempt for another one to be worth making.
//
// Failures are paced by the same escalating interval callers are told to wait,
// rather than by the flat debounce window. The window exists to stop repeated
// presentation of a token whose fate is unknown, and the escalation already
// does that while growing with the failure count. Using the window as well
// would leave a provider whose access tokens are shorter than it unusable for
// the rest of every window after a single hiccup.
//
// A record with no failures is not covered here; the plain debounce applies.
func (s *Store) failureBackoffElapsed(rec record) bool {
	n := rec.GetConsecutiveFailures()
	if n == 0 || isZeroTime(rec.GetLastFailureAt()) {
		return false
	}
	return !s.now().Before(writeAnchor(rec, rec.GetLastFailureAt()).Add(retryAfterFor(n)))
}

// canRePresent reports whether presenting this record's refresh token again is
// harmless. Every completed refresh on the family returned the same token, so a
// second presentation consumes nothing and cannot trip reuse detection. A record
// that has never completed a refresh does not qualify: rotation_observed being
// false there means nothing was observed, not that the provider does not rotate.
func canRePresent(rec record) bool {
	return rec.GetGeneration() > 0 && !rec.GetRotationObserved()
}

// writeAnchor ages a self-stamped time against the databroker's own clock.
//
// The stamp cannot be trusted on its own: a replica whose clock runs fast writes
// a time in the future, which would stretch every other replica's view of that
// record by the skew. The databroker's timestamp for the record cannot replace
// it either, because it moves with every later write — a failed attempt commits
// its failure counters, and that must not make an old successful refresh look
// recent.
//
// Taking the earlier of the two keeps a stamp that cannot be later than the
// write that carried it, which is what makes replicas need to agree with the
// databroker rather than with each other.
func writeAnchor(rec record, selfStamped *timestamppb.Timestamp) time.Time {
	if isZeroTime(selfStamped) {
		// Written by something that stamped no time at all. The databroker's own
		// timestamp still ages it, so it is not treated as permanently fresh.
		return rec.modifiedAt
	}
	stamped := selfStamped.AsTime()
	if rec.modifiedAt.IsZero() || stamped.Before(rec.modifiedAt) {
		return stamped
	}
	return rec.modifiedAt
}

// claim runs the acceptance predicate inside a flight and, when it calls for
// one, commits the write-ahead intent that authorizes a single presentation.
func (s *Store) claim(ctx context.Context, id string, opt liveOptions) (outcome, error) {
	s.setRecordOptions(ctx)

	// Called only from begin, which has already detached from the caller: the
	// server commits the intent before the acknowledgement gets back here, so a
	// caller cancelled in that window would leave an intent nobody owns. The
	// deadline is taken from that detached context rather than from a fresh one,
	// so this flight counts against the same budget the attempt after it does.
	flightCtx, cancel := context.WithTimeout(ctx, commitTimeout)
	defer cancel()

	var out outcome
	// Reported after the flight for the same reason as in Revoke: the callback
	// can run more than once.
	var retired record
	var changed []*databroker.Record
	var shared bool
	var err error
	for attempt := range maxWriteAttempts {
		out = outcome{}
		changed, shared, err = databrokerutil.Do(flightCtx, s.client, id, func(tx databrokerutil.TX) error {
			rec, err := txGet(flightCtx, tx, id)
			if errors.Is(err, errRecordNotFound) {
				out = outcome{kind: outcomeAbsent}
				return nil
			} else if err != nil {
				return err
			}
			out = s.decide(rec, opt)
			switch out.kind {
			case outcomeResolveDead:
				markDead(rec, deadReasonUnknownOutcome, s.now())
				if err := txPut(flightCtx, tx, rec); err != nil {
					return err
				}
				retired = rec
				out = outcome{kind: outcomeDead, rec: rec}
			case outcomeClaim:
				rec.RefreshAttemptId = uuid.NewString()
				rec.RefreshStartedAt = timestamppb.New(s.now())
				rec.PresentedGeneration = rec.GetGeneration()
				if err := txPut(flightCtx, tx, rec); err != nil {
					return err
				}
				out = outcome{kind: outcomeClaimed, rec: rec, probe: out.probe}
			}
			return nil
		})
		if err == nil || !retryableFlightError(ctx, err) {
			break
		}
		// The stream was torn down. If this caller's intent had already been
		// committed, the record now carries its id and the attempt is this
		// caller's to make; otherwise nothing was written and the flight is worth
		// opening again. Without this the intent would be stranded, and every
		// consumer of this user would wait out the settle window for a databroker
		// blip.
		if out.kind == outcomeClaimed {
			if rec, gerr := s.get(ctx, id); gerr == nil &&
				rec.GetRefreshAttemptId() == out.rec.GetRefreshAttemptId() {
				return outcome{kind: outcomeClaimed, rec: rec, probe: out.probe}, nil
			}
		}
		if attempt == maxWriteAttempts-1 {
			break
		}
		if werr := s.wait(ctx); werr != nil {
			return outcome{}, storeError(werr)
		}
	}
	if err != nil {
		return outcome{}, storeError(err)
	}
	if retired.UpstreamIdPSession != nil {
		s.recordRetired(ctx, retired, deadReasonUnknownOutcome,
			"idpsession: an abandoned refresh attempt was retired without presenting its token")
	}
	if !shared {
		return out, nil
	}

	// Suppressed, so this caller's work never ran. Evaluate the same predicate
	// against what the flight that ran committed. The flight returns those
	// records, so no re-read is needed and a follower's lagging read is avoided.
	// A flight that committed no write, because it adopted a usable record,
	// returns no records; only then re-read.
	rec, err := changedRecord(changed, id)
	committed := err == nil
	if errors.Is(err, errRecordNotFound) {
		rec, err = s.get(ctx, id)
	}
	if errors.Is(err, errRecordNotFound) {
		return outcome{kind: outcomeAbsent}, nil
	} else if err != nil {
		return outcome{}, storeError(err)
	}
	out = s.decide(rec, opt)
	switch {
	case out.kind.needsWrite():
		// The record needs a write, but a suppressed caller never got a
		// transaction to write it in. Ask again.
		return outcome{kind: outcomeContended, rec: rec}, nil
	case out.kind == outcomeDead && !committed:
		// A tombstone read from a plain lookup rather than from what the flight
		// committed, so it may be a follower still serving a record a login has
		// since superseded. Ending the grant is the one verdict that costs the
		// user a login to undo, so ask again rather than take it from a read that
		// may lag.
		return outcome{kind: outcomeContended, rec: rec}, nil
	}
	return out, nil
}

// attempt presents the refresh token to the IdP with the intent committed, then
// commits the outcome. It never leaves the record in a state that would let a
// later caller present a token this attempt may already have consumed.
//
// Once the intent is committed an outcome must be committed too, so this runs on
// a context detached from the caller's. If a pod restart, a disconnected MCP
// client or a lost manager lease cancelled the caller here, nothing would be
// written and the intent would resolve to a dead record one settle window later.
// The caller's context still governs everything before the claim, and the
// deadlines below bound the detached work.
func (s *Store) attempt(ctx context.Context, id string, claimed outcome) (outcome, error) {
	tok, capture, refreshErr := s.callIDP(ctx, claimed.rec) // bounded by refreshTimeout

	// Classified once for the whole attempt: classify logs the misconfiguration
	// class at error level, so calling it again for the metric would report the
	// same failure twice.
	class := classSucceeded
	if refreshErr != nil {
		class = classify(ctx, refreshErr)
	}
	metrics.RecordIdpSessionPresentation(ctx, class.String())

	// Deliberately outside the envelope begin created. Once an intent is
	// committed its outcome must be committed too, whatever the claim and the IdP
	// call have already spent: sharing one budget with them means a slow claim
	// plus a slow refresh can leave the write nothing, which strands the intent
	// and is the one state this must never produce. The cost is that the
	// detached ceiling is the envelope plus this, which settleDelay accounts for.
	commitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), commitTimeout)
	defer cancel()

	// One stamp for the whole attempt, so a commit that runs twice because its
	// acknowledgement was lost recognizes its own effect. See commitAttempt.
	at := s.now()

	var out outcome
	err := s.do(commitCtx, id, func(tx databrokerutil.TX) error {
		rec, err := txGet(commitCtx, tx, id)
		switch {
		case errors.Is(err, errRecordNotFound) && refreshErr != nil:
			// The record vanished (legacy delete or GC) and the refresh also
			// failed, so there is nothing to write and nothing was consumed.
			out = outcome{kind: outcomeAbsent}
			return nil
		case errors.Is(err, errRecordNotFound):
			// The record vanished during the IdP call but the refresh succeeded,
			// so this attempt holds the newest token in the family. Discarding it
			// would report ErrNoUpstreamSession, whose remedy is for consumers to
			// Register their own, by now consumed, copy. Write the rotation back
			// instead.
			rec = record{
				UpstreamIdPSession: proto.Clone(claimed.rec.UpstreamIdPSession).(*oauth21proto.UpstreamIdPSession),
			}
		case err != nil:
			return err
		case rec.GetRefreshAttemptId() != claimed.rec.GetRefreshAttemptId() ||
			rec.GetPresentedGeneration() != claimed.rec.GetPresentedGeneration():
			// Superseded, revoked, or resolved during the IdP call. This result
			// describes a grant that is no longer canonical, so writing it would
			// resurrect the superseded one.
			out = outcome{kind: outcomeContended}
			return nil
		}
		out = s.commitAttempt(ctx, rec, claimed, tok, capture, refreshErr, class, at)
		return txPut(commitCtx, tx, rec)
	})
	if err != nil {
		return outcome{}, err
	}
	if out.kind == outcomeDead {
		s.recordRetired(ctx, out.rec, out.rec.GetDeadReason(),
			"idpsession: the identity provider refused this grant")
	}
	return out, nil
}

// commitAttempt writes the attempt's outcome into rec and reports it. rec is
// always written back, because errors cross a flight as text: an outcome that
// exists only as a flight error is invisible to every other process.
func (s *Store) commitAttempt(
	_ context.Context,
	rec record,
	claimed outcome,
	tok *oauth2.Token,
	capture *claimsCapture,
	refreshErr error,
	class refreshClass,
	now time.Time,
) outcome {
	if refreshErr == nil {
		rec.UpstreamAccessToken = tok.AccessToken
		rec.TokenType = tok.TokenType
		if tok.RefreshToken != "" {
			if tok.RefreshToken != claimed.rec.GetUpstreamRefreshToken() {
				// Sticky. Presenting this grant's token consumes it, so from now
				// on it must not be presented twice. A response carrying no
				// refresh token does not reach here and leaves the field false:
				// the stored token was not replaced, so the family has still
				// never been seen to rotate.
				rec.RotationObserved = true
			}
			rec.UpstreamRefreshToken = tok.RefreshToken
		}
		// Many IdPs omit id_token, and so claims, on refresh. Keep the last-known
		// values rather than blanking them, unless the provider was asked to
		// overwrite the ID token and reported that there is none, which is a
		// withdrawal every projection has to see.
		if capture.rawIDTokenSet {
			rec.RawIdToken = capture.rawIDToken
			rec.RawIdTokenCleared = capture.rawIDToken == ""
		}
		if len(capture.claims) > 0 {
			rec.Claims = capture.claims.ToPB()
		}
		rec.RefreshedAt = timestamppb.New(now)
		rec.ExpiresAt = timestamppb.New(tok.Expiry)
		rec.Generation++
		rec.ConsecutiveFailures = 0
		rec.State = oauth21proto.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_LIVE
		clearIntent(rec)
		return outcome{kind: outcomeLive, rec: rec, presented: true}
	}

	// Only once per attempt. An ambiguous outcome keeps the intent, so a commit
	// retried after a lost acknowledgement still passes the ownership check and
	// reaches here a second time; counting again would double the backoff this
	// one failure earns.
	if !rec.GetLastFailureAt().AsTime().Equal(now) {
		rec.LastFailureAt = timestamppb.New(now)
		rec.ConsecutiveFailures++
	}

	switch class {
	case classPermanent:
		reason := deadReasonIDPRevoked
		switch {
		case claimed.probe:
			// A probe re-presented a token after a settled intent, so a refusal
			// cannot be told apart from the earlier attempt having consumed it.
			reason = deadReasonUnknownOutcome
		case rec.GetGeneration() == 0 && isZeroTime(rec.GetRefreshedAt()):
			// This record never completed a refresh, so the seed was invalid
			// rather than a live session being revoked.
			reason = deadReasonSeedInvalid
		}
		markDead(rec, reason, now)
		return outcome{kind: outcomeDead, rec: rec}
	case classKnownFailed:
		// The IdP, or something answering for it, returned a failure, so the token
		// was not consumed. Clearing the intent keeps a single 503 from retiring a
		// rotating grant once the settle window passes.
		clearIntent(rec)
		return outcome{kind: outcomeTransient, err: refreshErr, rec: rec}
	default: // classAmbiguous
		// The request may have been delivered and processed. The intent stays so
		// nothing presents this token again; the settle policy resolves it later.
		return outcome{kind: outcomeTransient, err: refreshErr, rec: rec}
	}
}

// callIDP presents the refresh token. It runs outside every transaction, because
// the databroker aborts a transaction after a minute and holding a flight across
// a network call blocks every other caller on the key.
func (s *Store) callIDP(
	ctx context.Context,
	rec record,
) (*oauth2.Token, *claimsCapture, error) {
	capture := newClaimsCapture()
	if rec.GetUpstreamRefreshToken() == "" {
		return nil, capture, fmt.Errorf("%w: the record holds no refresh token", errNotSent)
	}
	if s.getAuthenticator == nil {
		// Configuration, not an outage: no retry fixes it, so it is logged at a
		// level that gets noticed rather than only surfacing as a retry hint.
		log.Ctx(ctx).Error().Str("idp-id", rec.GetIdpId()).
			Msg("idpsession: no authenticator getter configured; upstream sessions cannot be refreshed")
		return nil, capture, fmt.Errorf("%w: no authenticator getter configured", errNotSent)
	}
	// Resolving the provider can itself perform discovery over the network, so
	// it runs under the same deadline as the refresh it is for.
	refreshCtx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()

	auth, err := s.getAuthenticator(refreshCtx, rec.GetIdpId())
	if err != nil {
		return nil, capture, fmt.Errorf("%w: get authenticator for %q: %w", errNotSent, rec.GetIdpId(), err)
	}
	if auth == nil {
		return nil, capture, fmt.Errorf("%w: no authenticator for idp %q", errNotSent, rec.GetIdpId())
	}

	tok, err := auth.Refresh(refreshCtx, &oauth2.Token{RefreshToken: rec.GetUpstreamRefreshToken()}, capture)
	return tok, capture, err
}

// do runs work in a flight keyed by id, retrying while another flight suppresses
// it. Unlike the EnsureLive claim, which adopts the outcome of the flight that
// ran, a write here has to actually happen, and a suppressed flight never runs
// work.
//
// Contract for work: it may run more than once, including against its own
// committed effect. The server commits before acknowledging, so a torn-down
// stream leaves this unable to tell a write that landed from one that did not,
// and asking again is the only way to find out. Each callback here satisfies
// that differently. Register writes only when the record is absent, Revoke
// returns early when it is already dead, Supersede compares the stored token,
// and the attempt commit checks it still owns the intent. Every one of them has
// to satisfy it. Anything with a side effect that must happen once, such as a
// metric or an operator-facing log, belongs outside the callback.
func (s *Store) do(ctx context.Context, id string, work func(databrokerutil.TX) error) error {
	s.setRecordOptions(ctx)

	for attempt := range maxWriteAttempts {
		_, shared, err := databrokerutil.Do(ctx, s.client, id, work)
		if err != nil && !retryableFlightError(ctx, err) {
			return storeError(err)
		}
		if err == nil && !shared {
			return nil
		}
		if attempt == maxWriteAttempts-1 {
			break
		}
		// Retrying immediately would spin against whichever flight holds the
		// key, at the rate of a databroker round trip.
		if err := s.wait(ctx); err != nil {
			return storeError(err)
		}
	}
	return transient("the record was busy for the whole write budget", nil, DefaultRetryAfter)
}

// setRecordOptions publishes recordTTL for the canonical record type, so the
// databroker collects records nothing has rewritten for that long. It runs
// before a flight is opened rather than in New, because a Store is rebuilt on
// every configuration change and construction does no I/O.
//
// Record collection is an optimization, not a correctness requirement, so a
// failure is logged and the caller's operation continues. The next operation
// tries again. Concurrent first callers may each send the request, which is
// harmless because it sets a value rather than changing one.
func (s *Store) setRecordOptions(ctx context.Context) {
	if s.optionsSet.Load() {
		return
	}
	// While it keeps failing, do not pay a serial round trip on every flight.
	if next := s.optionsRetryAt.Load(); next != nil && s.now().Before(*next) {
		return
	}
	_, err := s.client.SetOptions(ctx, &databroker.SetOptionsRequest{
		Type:    recordTypeURL,
		Options: &databroker.Options{Ttl: durationpb.New(recordTTL)},
	})
	if err != nil {
		retryAt := s.now().Add(optionsRetryInterval)
		s.optionsRetryAt.Store(&retryAt)
		log.Ctx(ctx).Warn().Err(err).
			Msg("idpsession: could not set the record ttl; expired records will not be collected")
		return
	}
	s.optionsSet.Store(true)
}

// retryableFlightError reports whether a failed flight is worth opening again.
//
// The transaction is a stream, and tearing one down races with the next one
// taking the same key: the loser sees the stream closed rather than a decision
// about the record. That is reported as a transport status, so it is
// indistinguishable from the caller having given up except by asking whether the
// caller actually did.
func retryableFlightError(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false // the caller really is gone
	}
	switch status.Code(err) {
	case codes.Canceled, codes.Aborted, codes.Unavailable:
		return true
	}
	return false
}

// wait sleeps a jittered poll interval so callers released together do not
// re-converge on the same instant.
func (s *Store) wait(ctx context.Context) error {
	d := pollMinDelay + mathrand.N(pollMaxDelay-pollMinDelay) //nolint:gosec // poll jitter, not security material
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-t.C:
		return nil
	}
}

// usable reports whether the record's stored access token is still valid with
// margin, or was refreshed within the debounce window. It is only a predicate;
// liveFromRecord builds the snapshot. Keeping them apart matters because
// flattening the stored claims is a JSON round trip, which should not run on
// paths that only need the answer, such as decide, which runs inside a flight.
func (s *Store) usable(rec record, opt liveOptions) bool {
	if rec.GetUpstreamAccessToken() == "" {
		return false
	}
	if isZeroTime(rec.GetExpiresAt()) {
		// The IdP returned no expires_in, so how long the token lasts is
		// unknown. Trust it for the debounce window and refresh again after,
		// which costs one IdP call per window. Reading it as already expired
		// would instead make the record never usable, so every caller but the
		// one that refreshed would get a transient error for the whole window.
		return s.debounced(rec)
	}
	now := s.now()
	exp := rec.GetExpiresAt().AsTime()
	if !now.Before(exp) {
		return false // already expired
	}
	if opt.requireFresh {
		// The caller wants liveness checked recently rather than a token that
		// merely has not expired, so only the debounce window vouches for it.
		// The expiry check above still applies: a provider whose access tokens
		// are shorter than that window would otherwise have an already-expired
		// token served into whatever the caller mints from it.
		return s.debounced(rec)
	}
	if now.Add(refreshGrace).Before(exp) {
		return true // still has margin
	}
	return s.debounced(rec) // liveness validated very recently
}

// debounced reports whether the record was refreshed recently enough that the
// refresh token must not be presented again.
func (s *Store) debounced(rec record) bool {
	if isZeroTime(rec.GetRefreshedAt()) {
		return false // nothing has ever been refreshed, so nothing to debounce
	}
	return s.now().Sub(writeAnchor(rec, rec.GetRefreshedAt())) < s.minRefreshInterval
}

func liveFromRecord(rec record) *Live {
	return &Live{
		Token: &oauth2.Token{
			AccessToken:  rec.GetUpstreamAccessToken(),
			TokenType:    rec.GetTokenType(),
			RefreshToken: rec.GetUpstreamRefreshToken(),
			Expiry:       rec.GetExpiresAt().AsTime(),
		},
		RawIDToken:        rec.GetRawIdToken(),
		RawIDTokenCleared: rec.GetRawIdTokenCleared(),
		Claims:            identity.NewFlattenedClaimsFromPB(rec.GetClaims()),
	}
}

// --- record state -----------------------------------------------------------

func isDead(rec record) bool {
	return rec.GetState() == oauth21proto.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_DEAD
}

// markDead turns rec into a tombstone. Secrets are cleared so a dead record is
// not a place to find a refresh token. generation and epoch are kept so a later
// Supersede can start a strictly newer epoch.
func markDead(rec record, reason string, at time.Time) {
	rec.State = oauth21proto.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_DEAD
	rec.DeadReason = reason
	rec.UpstreamRefreshToken = ""
	rec.UpstreamAccessToken = ""
	rec.TokenType = ""
	rec.RawIdToken = ""
	rec.Claims = nil
	rec.ExpiresAt = nil
	rec.LastFailureAt = timestamppb.New(at)
	clearIntent(rec)
}

func clearIntent(rec record) {
	rec.RefreshAttemptId = ""
	rec.RefreshStartedAt = nil
	rec.PresentedGeneration = 0
}

func isZeroTime(ts *timestamppb.Timestamp) bool {
	return ts.AsTime().Unix() <= 0
}

// --- error classification ---------------------------------------------------

// errNotSent marks a failure that happened before the request was built, so the
// token was never presented.
var errNotSent = errors.New("idpsession: refresh was not attempted")

type refreshClass int

const (
	// classPermanent: the IdP reported that this grant is over.
	classPermanent refreshClass = iota
	// classKnownFailed: a failure was returned, or the request was never sent, so
	// the token was not consumed.
	classKnownFailed
	// classAmbiguous: the request may have reached the IdP and may still be
	// processed, so nothing may present this token again.
	classAmbiguous
	// classSucceeded: there was no error. It is not produced by classify, only
	// by the caller that already knows.
	classSucceeded
)

// String labels the class for metrics.
func (c refreshClass) String() string {
	switch c {
	case classSucceeded:
		return "success"
	case classPermanent:
		return "refused"
	case classKnownFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// classify decides what a refresh error means for the token. Ambiguous cases
// resolve toward not reporting a sign-out and not assuming the token survived an
// outcome that was never observed.
func classify(ctx context.Context, err error) refreshClass {
	if err == nil {
		return classKnownFailed
	}

	// Nothing was sent.
	if errors.Is(err, errNotSent) {
		return classKnownFailed
	}

	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) {
		switch oauth21.ErrorCode(retrieveErr.ErrorCode) {
		case oauth21.InvalidGrant:
			return classPermanent
		case oauth21.InvalidClient, oauth21.UnauthorizedClient, oauth21.InvalidRequest:
			// Pomerium's own credentials or request are wrong. Keep the sessions:
			// a rotated client secret must not sign out every user.
			log.Ctx(ctx).Error().Err(err).
				Str("error-code", retrieveErr.ErrorCode).
				Msg("idpsession: the identity provider rejected pomerium's own client credentials or request; upstream sessions are kept, fix the provider configuration")
			return classKnownFailed
		}
		var status int
		if retrieveErr.Response != nil {
			status = retrieveErr.Response.StatusCode
		}
		switch status {
		case http.StatusBadGateway, http.StatusGatewayTimeout, http.StatusRequestTimeout:
			// A gateway answering for the IdP says nothing about whether the IdP
			// processed the request.
			return classAmbiguous
		}
		// A response was delivered (5xx, 429, or an unrecognized error code), so
		// the request failed at the IdP before the grant was applied.
		//
		// Known gap: an IdP that returns a bare 500 after committing the rotation
		// is read here as "not consumed", stranding the rotated token. Gateway
		// statuses (502/504/408) are handled above as ambiguous; treating every
		// 500 that way would retire a rotating grant on any origin hiccup.
		return classKnownFailed
	}

	// Connection-establishment failures happen before the request is written.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return classKnownFailed
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return classKnownFailed
	}

	// Timeouts, resets and truncated responses. The request may have been
	// delivered and acted upon.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "connection reset") {
		return classAmbiguous
	}

	// Unknown. Prefer no replay over reporting a sign-out that was not observed.
	return classAmbiguous
}

// --- databroker helpers -----------------------------------------------------

func (s *Store) get(ctx context.Context, id string) (record, error) {
	res, err := s.client.Get(ctx, &databroker.GetRequest{
		Type: recordTypeURL,
		Id:   id,
	})
	if databroker.IsNotFound(err) {
		return record{}, errRecordNotFound
	}
	if err != nil {
		return record{}, storeError(err)
	}
	rec, err := decodeRecord(res.GetRecord())
	return rec, storeError(err)
}

// txGet reads the canonical record inside a flight. It queries by id instead of
// using Get because Get of an absent record fails the whole transaction, and
// absent is a normal outcome here: nothing seeded yet, or a legacy tombstone.
func txGet(ctx context.Context, tx databrokerutil.TX, id string) (record, error) {
	req := &databroker.QueryRequest{
		Type:  recordTypeURL,
		Limit: 1,
	}
	req.SetFilterByID(id)
	res, err := tx.Query(ctx, req)
	if err != nil {
		return record{}, err
	}
	records := res.GetRecords()
	if len(records) == 0 {
		return record{}, errRecordNotFound
	}
	return decodeRecord(records[0])
}

// txPut writes the canonical record inside a flight.
func txPut(ctx context.Context, tx databrokerutil.TX, rec record) error {
	_, err := tx.Put(ctx, &databroker.PutRequest{Records: []*databroker.Record{newRecord(rec.UpstreamIdPSession)}})
	return err
}

// changedRecord picks the canonical record out of the committed records a flight
// returns to suppressed callers, or errRecordNotFound if that commit did not
// write it.
func changedRecord(changed []*databroker.Record, id string) (record, error) {
	for _, rec := range changed {
		if rec.GetId() == id {
			return decodeRecord(rec)
		}
	}
	return record{}, errRecordNotFound
}

// record is the canonical session plus the databroker metadata the store needs.
// modifiedAt is stamped by the databroker rather than by the writing replica, so
// comparing it against the local clock narrows the skew that matters from
// replica-against-replica to replica-against-databroker.
type record struct {
	*oauth21proto.UpstreamIdPSession
	modifiedAt time.Time
}

// decodeRecord decodes a databroker record into the canonical session. It is
// called from get (a direct read) and txGet (a query inside a flight). A nil
// record, or one carrying a legacy DeletedAt tombstone written before death was
// stored as state, reads as errRecordNotFound, the same as a record that was
// never seeded.
func decodeRecord(rec *databroker.Record) (record, error) {
	if rec == nil || rec.GetDeletedAt() != nil {
		return record{}, errRecordNotFound
	}
	out := new(oauth21proto.UpstreamIdPSession)
	if err := rec.GetData().UnmarshalTo(out); err != nil {
		// Retrying cannot fix stored bytes that do not parse, so this is neither
		// a transient failure nor a statement about the grant.
		return record{}, fmt.Errorf("%w: %w", ErrRecordUndecodable, err)
	}
	return record{UpstreamIdPSession: out, modifiedAt: rec.GetModifiedAt().AsTime()}, nil
}

func newRecord(rec *oauth21proto.UpstreamIdPSession) *databroker.Record {
	data := protoutil.NewAny(rec)
	return &databroker.Record{
		Id:   rec.GetId(),
		Data: data,
		Type: data.GetTypeUrl(),
	}
}

// --- claims capture ---------------------------------------------------------

// claimsCapture implements identity.State and json.Unmarshaler so it can collect
// the ID-token claims the authenticator writes during Refresh. It cannot reuse
// manager.SessionUnmarshaler, which writes into a *session.Session that does not
// exist here.
type claimsCapture struct {
	rawIDToken string
	// rawIDTokenSet distinguishes a provider that sent no id_token from one that
	// deliberately cleared it. pkg/identity/oidc sets an empty raw ID token when
	// overwrite_id_token_on_refresh is configured and the refresh response
	// carries none, and that clear has to reach the record: treating it as
	// "nothing seen" would keep serving an assertion the provider withdrew.
	rawIDTokenSet bool
	claims        identity.FlattenedClaims
}

func newClaimsCapture() *claimsCapture {
	return &claimsCapture{claims: identity.FlattenedClaims{}}
}

func (c *claimsCapture) SetRawIDToken(rawIDToken string) {
	c.rawIDToken = rawIDToken
	c.rawIDTokenSet = true
}

func (c *claimsCapture) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// Keep only user-info claims. This filter is duplicated from
	// manager.SessionUnmarshaler; the two must agree, or a session recreated here
	// and one refreshed by the manager would carry different claims.
	delete(raw, "iss")
	delete(raw, "sub")
	delete(raw, "exp")
	delete(raw, "iat")
	maps.Copy(c.claims, identity.NewClaimsFromRaw(raw).Flatten())
	return nil
}
