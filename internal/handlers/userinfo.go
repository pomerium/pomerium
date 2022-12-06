package handlers

import (
	"encoding/json"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/ui"
	"github.com/pomerium/webauthn"
)

// UserInfoData is the data for the UserInfo page.
type UserInfoData struct {
	CSRFToken      string
	IsImpersonated bool
	Session        *session.Session
	User           *user.User
	Profile        *identity.Profile

	IsEnterprise    bool
	DirectoryUser   *directory.User
	DirectoryGroups []*directory.Group

	WebAuthnCreationOptions *webauthn.PublicKeyCredentialCreationOptions
	WebAuthnRequestOptions  *webauthn.PublicKeyCredentialRequestOptions
	WebAuthnURL             string

	BrandingOptions httputil.BrandingOptions
}

// ToJSON converts the data into a JSON map.
func (data UserInfoData) ToJSON() map[string]any {
	m := map[string]any{}
	m["csrfToken"] = data.CSRFToken
	m["isImpersonated"] = data.IsImpersonated
	if bs, err := protojson.Marshal(data.Session); err == nil {
		m["session"] = json.RawMessage(bs)
	}
	if bs, err := protojson.Marshal(data.User); err == nil {
		m["user"] = json.RawMessage(bs)
	}
	if bs, err := protojson.Marshal(data.Profile); err == nil {
		m["profile"] = json.RawMessage(bs)
	}
	m["isEnterprise"] = data.IsEnterprise
	if data.DirectoryUser != nil {
		m["directoryUser"] = data.DirectoryUser
	}
	if len(data.DirectoryGroups) > 0 {
		m["directoryGroups"] = data.DirectoryGroups
	}
	m["webAuthnCreationOptions"] = data.WebAuthnCreationOptions
	m["webAuthnRequestOptions"] = data.WebAuthnRequestOptions
	m["webAuthnUrl"] = data.WebAuthnURL
	httputil.AddBrandingOptionsToMap(m, data.BrandingOptions)
	return m
}

// UserInfo returns a handler that renders the user info page.
func UserInfo(data UserInfoData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServePage(w, r, "UserInfo", data.ToJSON())
	})
}
