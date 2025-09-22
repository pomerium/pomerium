package handlers

import (
	"net/http"

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
	m["isImpersonated"] = data.IsImpersonated
	m["session"] = data.sessionJSON()
	m["user"] = data.userJSON()
	m["profile"] = data.profileJSON()
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

func (data UserInfoData) profileJSON() map[string]any {
	if data.Profile == nil {
		return nil
	}

	m := map[string]any{}
	m["claims"] = data.Profile.GetClaims().AsMap()
	return m
}

func (data UserInfoData) sessionJSON() map[string]any {
	if data.Session == nil {
		return nil
	}

	m := map[string]any{}
	claims := make(map[string]any)
	for k, vs := range data.Session.GetClaims() {
		claims[k] = vs.AsSlice()
	}
	m["claims"] = claims
	var deviceCredentials []any
	for _, dc := range data.Session.GetDeviceCredentials() {
		deviceCredentials = append(deviceCredentials, map[string]any{
			"typeId": dc.GetTypeId(),
			"id":     dc.GetId(),
		})
	}
	m["deviceCredentials"] = deviceCredentials
	m["expiresAt"] = data.Session.GetExpiresAt().AsTime()
	m["id"] = data.Session.GetId()
	m["userId"] = data.Session.GetUserId()
	return m
}

func (data UserInfoData) userJSON() map[string]any {
	if data.User == nil {
		return nil
	}

	m := map[string]any{}
	claims := make(map[string]any)
	for k, vs := range data.User.GetClaims() {
		claims[k] = vs.AsSlice()
	}
	m["claims"] = claims
	m["deviceCredentialIds"] = data.User.GetDeviceCredentialIds()
	m["id"] = data.User.GetId()
	m["name"] = data.User.GetName()
	return m
}

// UserInfo returns a handler that renders the user info page.
func UserInfo(data UserInfoData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServePage(w, r, "UserInfo", "User Info Dashboard", data.ToJSON())
	})
}
