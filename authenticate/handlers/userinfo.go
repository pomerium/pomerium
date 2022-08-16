package handlers

import (
	"encoding/json"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/ui"
	"github.com/pomerium/webauthn"
)

// UserInfoData is the data for the UserInfo page.
type UserInfoData struct {
	CSRFToken       string
	DirectoryGroups []*directory.Group
	DirectoryUser   *directory.User
	IsImpersonated  bool
	Session         *session.Session
	User            *user.User

	WebAuthnCreationOptions *webauthn.PublicKeyCredentialCreationOptions
	WebAuthnRequestOptions  *webauthn.PublicKeyCredentialRequestOptions
	WebAuthnURL             string

	BrandingOptions httputil.BrandingOptions
}

// ToJSON converts the data into a JSON map.
func (data UserInfoData) ToJSON() map[string]any {
	m := map[string]any{}
	m["csrfToken"] = data.CSRFToken
	var directoryGroups []json.RawMessage
	for _, directoryGroup := range data.DirectoryGroups {
		if bs, err := protojson.Marshal(directoryGroup); err == nil {
			directoryGroups = append(directoryGroups, json.RawMessage(bs))
		}
	}
	m["directoryGroups"] = directoryGroups
	if bs, err := protojson.Marshal(data.DirectoryUser); err == nil {
		m["directoryUser"] = json.RawMessage(bs)
	}
	m["isImpersonated"] = data.IsImpersonated
	if bs, err := protojson.Marshal(data.Session); err == nil {
		m["session"] = json.RawMessage(bs)
	}
	if bs, err := protojson.Marshal(data.User); err == nil {
		m["user"] = json.RawMessage(bs)
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
