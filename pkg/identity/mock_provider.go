package identity

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/pkg/identity/identity"
)

// MockProvider provides a mocked implementation of the providers interface.
type MockProvider struct {
	AuthenticateResponse oauth2.Token
	AuthenticateError    error
	RefreshResponse      oauth2.Token
	RefreshError         error
	RevokeError          error
	UpdateUserInfoError  error
	SignInError          error
	SignOutError         error
}

// Authenticate is a mocked providers function.
func (mp MockProvider) Authenticate(context.Context, string, identity.State) (*oauth2.Token, error) {
	return &mp.AuthenticateResponse, mp.AuthenticateError
}

// Refresh is a mocked providers function.
func (mp MockProvider) Refresh(context.Context, *oauth2.Token, identity.State) (*oauth2.Token, error) {
	return &mp.RefreshResponse, mp.RefreshError
}

// Revoke is a mocked providers function.
func (mp MockProvider) Revoke(_ context.Context, _ *oauth2.Token) error {
	return mp.RevokeError
}

// UpdateUserInfo is a mocked providers function.
func (mp MockProvider) UpdateUserInfo(_ context.Context, _ *oauth2.Token, _ any) error {
	return mp.UpdateUserInfoError
}

// Name returns the provider name.
func (mp MockProvider) Name() string {
	return "mock"
}

// SignOut is a mocked providers function.
func (mp MockProvider) SignOut(_ http.ResponseWriter, _ *http.Request, _, _, _ string) error {
	return mp.SignOutError
}

// SignIn is a mocked providers function.
func (mp MockProvider) SignIn(_ http.ResponseWriter, _ *http.Request, _ string) error {
	return mp.SignInError
}

// VerifyAccessToken verifies an access token.
func (mp MockProvider) VerifyAccessToken(_ context.Context, _ string) (claims map[string]any, err error) {
	return nil, fmt.Errorf("VerifyAccessToken not implemented")
}

// VerifyIdentityToken verifies an identity token.
func (mp MockProvider) VerifyIdentityToken(_ context.Context, _ string) (claims map[string]any, err error) {
	return nil, fmt.Errorf("VerifyIdentityToken not implemented")
}
