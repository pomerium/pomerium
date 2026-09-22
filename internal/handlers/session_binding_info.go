package handlers

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/ui"
)

type SessionInfoData struct {
	UserInfoData
	SessionData   []SessionBindingData
	ReAuthEnabled bool
	// Highlight is the SessionBindingID of a single row the page should call
	// out, e.g. the run a user has just approved. An id that matches no row
	// highlights nothing.
	Highlight string
}

type SessionBindingData struct {
	SessionBindingID         string
	Protocol                 string
	Resource                 string
	ClientAddress            string
	InitiatedAt              string
	ExpiresAt                string
	RevokeSessionBindingURL  string
	RevokeIdentityBindingURL string
	IsCurrentBrowser         bool
	HasIdentityBinding       bool
	DetailsSSH               *ProtocolDetailsSSH
	DetailsAgentic           *ProtocolDetailsAgentic
}

type ProtocolDetailsSSH struct {
	FingerprintID string
	SourceAddress string
}

// ProtocolDetailsAgentic is what an approved agentic run shows the person whose
// IdP session it borrows: what the agent is, what it is running on, and what
// they said yes to. Without it the row is a bare uuid, which is not enough to
// decide whether to revoke.
type ProtocolDetailsAgentic struct {
	// RunID is the run's stable handle, quotable in a bug report.
	RunID string
	// Labels are the caller's descriptive attributes (template name, and
	// whatever else the caller set), frozen at approval.
	Labels map[string]string
	// Prompt is the approved request verbatim, bounded at creation. The page
	// truncates it to one line and shows the whole thing on hover.
	Prompt string
	// WorkloadClaims is the executor identity the run is sealed to — the
	// session's act.* claims with that prefix stripped, e.g.
	// "kubernetes.io.pod.name".
	WorkloadClaims map[string]string
}

func (data SessionInfoData) ToJSON() map[string]any {
	m := data.UserInfoData.ToJSON()
	m["sessionBindings"] = data.SessionData
	m["reauth_enabled"] = data.ReAuthEnabled
	m["highlight"] = data.Highlight
	return m
}

func ServeSessionBindingInfo(data SessionInfoData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServePage(w, r, "SessionBindingInfo", "Session Bindings", data.ToJSON())
	})
}
