package authenticate

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/pkce"
)

const (
	pkceCookieSuffix   = "_pkce"
	pkceCookieTTL      = 5 * time.Minute // Must cover auth code flow + browser clock skew.
	pkceCookieKeyBytes = 16              // 128-bit truncated HMAC for compact cookie names.
)

// errPKCEVerifierExpired is returned when the PKCE cookie is missing or TTL-expired.
var errPKCEVerifierExpired = errors.New("pkce verifier expired or missing")

type pkceEntry struct {
	Verifier string `json:"v"`
	IssuedAt int64  `json:"iat"`
}

// pkceStore manages per-state PKCE verifiers in encrypted, host-only cookies.
// It is safe for concurrent use; all fields are immutable after construction.
type pkceStore struct {
	cipher       cipher.AEAD
	hmacKey      []byte
	cookiePrefix string
	sameSite     http.SameSite
	ttl          time.Duration
	now          func() time.Time
}

func newPKCEStore(options *config.Options, cipher cipher.AEAD, cookieSecret []byte) *pkceStore {
	return &pkceStore{
		cipher:       cipher,
		hmacKey:      cookieSecret,
		cookiePrefix: options.CookieName + pkceCookieSuffix,
		sameSite:     options.GetCSRFSameSite(),
		ttl:          pkceCookieTTL,
		now:          time.Now,
	}
}

// InitVerifier generates a PKCE verifier, stores it in a cookie keyed by state,
// and returns a context carrying the PKCE parameters for the sign-in redirect.
func (s *pkceStore) InitVerifier(ctx context.Context, w http.ResponseWriter, state string) (context.Context, error) {
	verifier := oauth2.GenerateVerifier()
	if err := s.store(w, state, verifier); err != nil {
		return ctx, err
	}
	return pkce.WithPKCE(ctx, pkce.Params{
		Verifier: verifier,
		Method:   "S256",
	}), nil
}

// PopVerifier retrieves and removes the stored PKCE verifier for the given state,
// returning a context carrying the PKCE parameters for the token exchange.
// Returns errPKCEVerifierExpired if the cookie is missing or TTL-expired.
func (s *pkceStore) PopVerifier(ctx context.Context, w http.ResponseWriter, r *http.Request, state string) (context.Context, error) {
	cookieName := s.cookieNameForState(state)
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return ctx, errPKCEVerifierExpired
	}
	entry, err := s.decode(cookieName, cookie.Value)
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("authenticate: failed to decode PKCE cookie; clearing")
		s.clear(w, cookieName)
		return ctx, err
	}
	s.clear(w, cookieName)
	if s.now().Sub(time.Unix(entry.IssuedAt, 0)) > s.ttl {
		return ctx, errPKCEVerifierExpired
	}
	return pkce.WithPKCE(ctx, pkce.Params{
		Verifier: entry.Verifier,
		Method:   "S256",
	}), nil
}

func (s *pkceStore) store(w http.ResponseWriter, state, verifier string) error {
	cookieName := s.cookieNameForState(state)
	now := s.now()
	entry := pkceEntry{
		Verifier: verifier,
		IssuedAt: now.Unix(),
	}
	value, err := s.encode(cookieName, entry)
	if err != nil {
		return err
	}
	s.setCookie(w, cookieName, value, now)
	return nil
}

func (s *pkceStore) cookieNameForState(state string) string {
	h := sha256.Sum256([]byte(state))
	return s.cookiePrefix + "_" + base64.RawURLEncoding.EncodeToString(h[:])
}

func (s *pkceStore) encode(cookieName string, entry pkceEntry) (string, error) {
	bs, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	enc := cryptutil.Encrypt(s.cipher, bs, []byte(cookieName))
	return base64.RawURLEncoding.EncodeToString(enc), nil
}

func (s *pkceStore) decode(cookieName, value string) (pkceEntry, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return pkceEntry{}, err
	}
	plaintext, err := cryptutil.Decrypt(s.cipher, raw, []byte(cookieName))
	if err != nil {
		return pkceEntry{}, err
	}
	var entry pkceEntry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		return pkceEntry{}, err
	}
	return entry, nil
}

func (s *pkceStore) setCookie(w http.ResponseWriter, cookieName, value string, now time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     endpoints.PathAuthenticateCallback,
		HttpOnly: true,
		Secure:   true,
		SameSite: s.sameSite,
		MaxAge:   int(s.ttl.Seconds()),
		Expires:  now.Add(s.ttl),
	})
}

func (s *pkceStore) clear(w http.ResponseWriter, cookieName string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     endpoints.PathAuthenticateCallback,
		HttpOnly: true,
		Secure:   true,
		SameSite: s.sameSite,
		MaxAge:   -1,
		Expires:  s.now().Add(-time.Hour),
	})
}

// shouldUsePKCE reports whether the authenticator's IdP advertises S256 PKCE support.
func shouldUsePKCE(authenticator identity.Authenticator) bool {
	provider, ok := authenticator.(pkce.MethodsProvider)
	if !ok {
		return false
	}
	for _, m := range provider.PKCEMethods() {
		if strings.EqualFold(m, "S256") {
			return true
		}
	}
	return false
}
