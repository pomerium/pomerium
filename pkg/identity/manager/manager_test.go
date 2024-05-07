package manager

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/pkg/identity/identity"
)

type mockAuthenticator struct {
	refreshResult       *oauth2.Token
	refreshError        error
	revokeError         error
	updateUserInfoError error
}

func (mock *mockAuthenticator) Refresh(_ context.Context, _ *oauth2.Token, _ identity.State) (*oauth2.Token, error) {
	return mock.refreshResult, mock.refreshError
}

func (mock *mockAuthenticator) Revoke(_ context.Context, _ *oauth2.Token) error {
	return mock.revokeError
}

func (mock *mockAuthenticator) UpdateUserInfo(_ context.Context, _ *oauth2.Token, _ any) error {
	return mock.updateUserInfoError
}
