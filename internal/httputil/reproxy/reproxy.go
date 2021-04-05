// Package reproxy contains a handler for re-proxying traffic through the http controlplane.
package reproxy

import (
	"crypto/cipher"
	"encoding/base64"
	"math/rand"
	"net/http"
	stdhttputil "net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// The Handler looks for an X-Pomerium-Reproxy-Policy header and if found re-proxies the request upstream
// to the destination.
//
// This is used to forward requests to Kubernetes with headers split to multiple values instead of coalesced via a
// comma.
type Handler struct {
	mu       sync.RWMutex
	cipher   cipher.AEAD
	options  *config.Options
	policies map[uint64]*config.Policy
}

// New creates a new Handler.
func New() *Handler {
	h := new(Handler)
	h.cipher, _ = cryptutil.NewAEADCipher(cryptutil.NewKey())
	h.policies = make(map[uint64]*config.Policy)
	return h
}

// DecryptPolicyID decrypts a policy id.
func (h *Handler) DecryptPolicyID(encryptedPolicyStr string) (uint64, error) {
	encryptedPolicy, err := base64.StdEncoding.DecodeString(encryptedPolicyStr)
	if err != nil {
		return 0, err
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	rawPolicy, err := cryptutil.Decrypt(h.cipher, encryptedPolicy, nil)
	if err != nil {
		return 0, err
	}

	return strconv.ParseUint(string(rawPolicy), 10, 64)
}

// EncryptPolicyID encrypts a policy id.
func (h *Handler) EncryptPolicyID(policyID uint64) string {
	rawPolicy := []byte(strconv.FormatUint(policyID, 10))

	h.mu.RLock()
	defer h.mu.RUnlock()

	encryptedPolicy := cryptutil.Encrypt(h.cipher, rawPolicy, nil)
	encryptedPolicyStr := base64.StdEncoding.EncodeToString(encryptedPolicy)
	return encryptedPolicyStr
}

// Middleware returns an HTTP middleware for handling reproxying.
func (h *Handler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encryptedPolicyStr := r.Header.Get(httputil.HeaderPomeriumReProxyPolicy)
		if encryptedPolicyStr == "" {
			next.ServeHTTP(w, r)
			return
		}

		policyID, err := h.DecryptPolicyID(encryptedPolicyStr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		h.mu.RLock()
		options := h.options
		policy, ok := h.policies[policyID]
		h.mu.RUnlock()

		if !ok {
			http.Error(w, "policy not found", http.StatusNotFound)
			return
		}

		// fix the impersonate group header
		if vs := r.Header.Values(httputil.HeaderImpersonateGroup); len(vs) > 0 {
			vs = strings.Split(strings.Join(vs, ","), ",")
			r.Header.Del(httputil.HeaderImpersonateGroup)
			for _, v := range vs {
				r.Header.Add(httputil.HeaderImpersonateGroup, v)
			}
		}

		var dsts []url.URL
		for _, wu := range policy.To {
			dsts = append(dsts, wu.URL)
		}
		if len(dsts) == 0 {
			http.Error(w, "policy destination not found", http.StatusNotFound)
			return
		}
		// regular rand is fine for this
		dst := dsts[rand.Intn(len(dsts))] // nolint:gosec

		h := stdhttputil.NewSingleHostReverseProxy(&dst)
		h.Transport = config.NewPolicyHTTPTransport(options, policy)
		h.ServeHTTP(w, r)
	})
}

// Update updates the handler with new configuration.
func (h *Handler) Update(cfg *config.Config) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var err error
	h.cipher, err = cryptutil.NewAEADCipherFromBase64(cfg.Options.SharedKey)
	if err != nil {
		log.Warn().Err(err).Msg("reproxy: error creating secret cipher")
		return
	}

	h.options = cfg.Options
	h.policies = make(map[uint64]*config.Policy)
	for i, p := range cfg.Options.Policies {
		id, err := p.RouteID()
		if err != nil {
			log.Warn().Err(err).Msg("httputil: error getting route id")
			continue
		}
		h.policies[id] = &cfg.Options.Policies[i]
	}
}
