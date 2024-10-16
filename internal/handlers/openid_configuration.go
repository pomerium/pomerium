package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/urlutil"
)

func OpenidConfiguration(w http.ResponseWriter, r *http.Request) {
	u := urlutil.GetAbsoluteURL(r)
	json.NewEncoder(w).Encode(map[string]string{
		"issuer":   u.ResolveReference(&url.URL{Path: "/"}).String(),
		"jwks_uri": u.ResolveReference(&url.URL{Path: "/.well-known/pomerium/jwks.json"}).String(),
	})
}
