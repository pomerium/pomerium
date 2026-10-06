package handlers

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/ui"
)

type BindingInfoData struct {
	UserInfoData
	RevokeSessionBindingURL  string
	RevokeIdentityBindingURL string
	CurrentIDPSessionID      string
	IDPSessionData           []IDPSessionData
	BindingData              []SessionBindingData
}

type IDPSessionData struct {
	IDPSessionID  string
	SID           string
	ClientAddress string
	Resource      string
	InitiatedAt   string
}

type SessionBindingData struct {
	IDPSessionID     string
	SessionBindingID string
	Protocol         string
	Resource         string
	ClientAddress    string
	InitiatedAt      string
	ExpiresAt        string
	// IsCurrentBrowser   bool
	HasIdentityBinding bool
	DetailsSSH         *ProtocolDetailsSSH
}

type ProtocolDetailsSSH struct {
	FingerprintID string
	SourceAddress string
}

func (data BindingInfoData) ToJSON() map[string]any {
	m := data.UserInfoData.ToJSON()
	m["idpSessions"] = data.IDPSessionData
	m["sessionBindings"] = data.BindingData
	m["currentIdpSessionId"] = data.CurrentIDPSessionID
	m["revokeSessionBindingUrl"] = data.RevokeSessionBindingURL
	m["revokeIdentityBindingUrl"] = data.RevokeIdentityBindingURL
	return m
}

func ServeSessionBindingInfo(data BindingInfoData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServePage(w, r, "SessionBindingInfo", "Session Bindings", data.ToJSON())
	})
}

type BindingInfoData struct {
	UserInfoData
	RevokeSessionBindingURL  string
	RevokeIdentityBindingURL string
	CurrentIDPSessionID      string
	IDPSessionData           []IDPSessionData
	BindingData              []SessionBindingData
}

type IDPSessionData struct {
	IDPSessionID  string
	SID           string
	ClientAddress string
	Resource      string
	InitiatedAt   string
}

// temporary struct to make build pass
type SessionBindingDataV2 struct {
	IDPSessionID     string
	SessionBindingID string
	Protocol         string
	Resource         string
	ClientAddress    string
	InitiatedAt      string
	ExpiresAt        string
	// IsCurrentBrowser   bool
	HasIdentityBinding bool
	DetailsSSH         *ProtocolDetailsSSH
}
