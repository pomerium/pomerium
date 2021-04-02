package httputil

import (
	"crypto/tls"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/pomerium/pomerium/internal/log"
)

// ReProxyMiddleware looks for an X-Pomerium-Reproxy-Destination header and if found re-proxies the request upstream
// to the destination.
//
// This is used to forward requests to Kubernetes with headers split to multiple values instead of coalesced via a
// comma.
var ReProxyMiddleware = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dstStr := r.Header.Get(HeaderPomeriumReProxyDestination)
		if dstStr == "" {
			next.ServeHTTP(w, r)
			return
		}

		dstStrs := strings.Split(dstStr, ",")
		// pick a random destination
		// regular rand is fine for this
		dstStr = dstStrs[rand.Intn(len(dstStrs))] // nolint:gosec
		log.Info().Str("dst", dstStr).Msg("reproxy http request")
		dst, err := url.Parse(dstStr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// fix the impersonate group header
		if vs := r.Header.Values(HeaderImpersonateGroup); len(vs) > 0 {
			vs = strings.Split(strings.Join(vs, ","), ",")
			r.Header.Del(HeaderImpersonateGroup)
			for _, v := range vs {
				r.Header.Add(HeaderImpersonateGroup, v)
			}
		}

		h := httputil.NewSingleHostReverseProxy(dst)
		t := http.DefaultTransport.(interface {
			Clone() *http.Transport
		}).Clone()
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		h.Transport = t
		h.ServeHTTP(w, r)
	})
}
