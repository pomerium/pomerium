// Package reproxy contains a handler for re-proxying traffic through the http controlplane.
package reproxy

import (
	"encoding/base64"
	"errors"
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
// comma. (https://github.com/kubernetes/kubernetes/issues/94683) If the upstream issue is fixed we will remove this.
type Handler struct {
	mu       sync.RWMutex
	key      []byte
	options  *config.Options
	policies map[uint64]*config.Policy
}

// New creates a new Handler.
func New() *Handler {
	h := new(Handler)
	h.policies = make(map[uint64]*config.Policy)
	return h
}

// GetPolicyIDFromHeaders gets a policy id from http headers. If no policy id is found
// or the HMAC isn't valid, false will be returned.
func (h *Handler) GetPolicyIDFromHeaders(headers http.Header) (uint64, bool) {
	policyStr := headers.Get(httputil.HeaderPomeriumReproxyPolicy)
	hmacStr := headers.Get(httputil.HeaderPomeriumReproxyPolicyHMAC)
	hmac, err := base64.StdEncoding.DecodeString(hmacStr)
	if err != nil {
		return 0, false
	}

	policyID, err := strconv.ParseUint(policyStr, 10, 64)
	if err != nil {
		return 0, false
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	return policyID, cryptutil.CheckHMAC([]byte(policyStr), hmac, h.key)
}

// GetPolicyIDHeaders returns http headers for the given policy id.
func (h *Handler) GetPolicyIDHeaders(policyID uint64) [][2]string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	s := strconv.FormatUint(policyID, 10)
	hmac := base64.StdEncoding.EncodeToString(cryptutil.GenerateHMAC([]byte(s), h.key))
	return [][2]string{
		{httputil.HeaderPomeriumReproxyPolicy, s},
		{httputil.HeaderPomeriumReproxyPolicyHMAC, hmac},
	}
}

// Middleware returns an HTTP middleware for handling reproxying.
func (h *Handler) Middleware(next http.Handler) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		policyID, ok := h.GetPolicyIDFromHeaders(r.Header)
		if !ok {
			next.ServeHTTP(w, r)
			return nil
		}

		h.mu.RLock()
		options := h.options
		policy, ok := h.policies[policyID]
		h.mu.RUnlock()

		if !ok || !policy.IsForKubernetes() {
			return httputil.NewError(http.StatusNotFound, errors.New("policy not found"))
		}

		// remove these headers from the request to kubernetes
		r.Header.Del(httputil.HeaderPomeriumReproxyPolicy)
		r.Header.Del(httputil.HeaderPomeriumReproxyPolicyHMAC)

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
			return httputil.NewError(http.StatusNotFound, errors.New("policy destination not found"))
		}
		// regular rand is fine for this
		dst := dsts[rand.Intn(len(dsts))] // nolint:gosec

		h := stdhttputil.NewSingleHostReverseProxy(&dst)
		h.Transport = config.NewPolicyHTTPTransport(options, policy)
		h.ServeHTTP(w, r)
		return nil
	})
}

// Update updates the handler with new configuration.
func (h *Handler) Update(cfg *config.Config) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.key, _ = base64.StdEncoding.DecodeString(cfg.Options.SharedKey)
	h.options = cfg.Options
	h.policies = make(map[uint64]*config.Policy)
	for i, p := range cfg.Options.Policies {
		id, err := p.RouteID()
		if err != nil {
			log.Warn().Err(err).Msg("reproxy: error getting route id")
			continue
		}
		h.policies[id] = &cfg.Options.Policies[i]
	}
}
