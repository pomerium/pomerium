package idpsession_test

import (
	context "context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	oauth2 "golang.org/x/oauth2"

	"github.com/pomerium/pomerium/pkg/identity"
)

type behaviour string

const (
	singleuse behaviour = "once"
	block     behaviour = "block"
	flaky     behaviour = "flaky"
	erroring  behaviour = "error"
)

type temporaryError struct{ error }

func (temporaryError) Temporary() bool { return true }

var errTemporaryIDP error = temporaryError{errors.New("temporary idp error")}

type authMock struct {
	idpID string
	identity.Authenticator

	mu sync.Mutex

	i         int
	issued    int
	presented map[string]struct{}

	grants  map[string]int
	revoked map[int]struct{}

	release     chan struct{}
	revokeCalls chan struct{}
}

// name determines behaviour, e.g. "normal-flaky" returns occasional temporary errors
// but does not consume on use. "once-flaky" returns occasianal temporary errors, but consumes
// tokens on use.
func newMockAuthenticator(idpID string) *authMock {
	return &authMock{
		idpID:     idpID,
		presented: make(map[string]struct{}),
		grants:    make(map[string]int),
		revoked:   make(map[int]struct{}),
		i:         0,
		mu:        sync.Mutex{},

		release:     make(chan struct{}),
		revokeCalls: make(chan struct{}, 1),
	}
}

func (m *authMock) hasBehaviour(b behaviour) bool {
	return strings.Contains(m.idpID, string(b))
}

func (m *authMock) Refresh(ctx context.Context, token *oauth2.Token, state identity.State) (*oauth2.Token, error) {
	if m.hasBehaviour(block) {
		<-m.release
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hasBehaviour(erroring) {
		return nil, errTemporaryIDP
	}
	if m.hasBehaviour(flaky) {
		m.i++
		if m.i%2 == 1 {
			return nil, errTemporaryIDP
		}
		return m.doRefresh(ctx, token, state)
	}
	return m.doRefresh(ctx, token, state)
}

var errInvalidGrant = errors.New("invalid_grant")

func (m *authMock) grantFor(token *oauth2.Token) (int, bool) {
	if grant, ok := m.grants[token.RefreshToken]; ok {
		return grant, true
	}
	grant, ok := m.grants[token.AccessToken]
	return grant, ok
}

func (m *authMock) doRefresh(_ context.Context, token *oauth2.Token, _ identity.State) (*oauth2.Token, error) {
	if token == nil {
		panic("bug: invalid behaviour")
	}
	refreshToken := token.RefreshToken

	grant, known := m.grantFor(token)
	if known {
		if _, ok := m.revoked[grant]; ok {
			return nil, errInvalidGrant
		}
	} else {
		m.issued++
		grant = m.issued
		m.grants[refreshToken] = grant
	}

	// doRefresh, replacing lines 110-114
	if m.hasBehaviour(singleuse) {
		if _, ok := m.presented[refreshToken]; ok {
			m.revoked[grant] = struct{}{} // replay kills the family
			return nil, errInvalidGrant
		}
	}

	m.presented[refreshToken] = struct{}{}

	m.issued++
	next := &oauth2.Token{
		AccessToken:  fmt.Sprintf("access-%d", m.issued),
		TokenType:    "Bearer",
		RefreshToken: fmt.Sprintf("refresh-%d", m.issued),
		Expiry:       time.Now().Add(time.Hour),
	}
	m.grants[next.AccessToken] = grant
	m.grants[next.RefreshToken] = grant
	return next, nil
}

func (m *authMock) Revoke(ctx context.Context, token *oauth2.Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.doRevoke(ctx, token)
	select {
	case m.revokeCalls <- struct{}{}:
	default:
	}
	return err
}

func (m *authMock) doRevoke(_ context.Context, token *oauth2.Token) error {
	if token == nil {
		panic("bug: invalid behaviour")
	}

	grant, ok := m.grantFor(token)
	if !ok {
		m.issued++
		grant = m.issued
		m.grants[token.RefreshToken] = grant
		m.grants[token.AccessToken] = grant
	}
	m.revoked[grant] = struct{}{}
	return nil
}

func newTestGetAuthenticator(t *testing.T) func(context.Context, string) (identity.Authenticator, error) {
	t.Helper()
	return newTestGetter(t)
}

func newTestGetter(t *testing.T) func(context.Context, string) (identity.Authenticator, error) {
	t.Helper()
	var mu sync.Mutex
	idpMap := map[string]identity.Authenticator{}
	return func(_ context.Context, idpID string) (identity.Authenticator, error) {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := idpMap[idpID]; !ok {
			idpMap[idpID] = newMockAuthenticator(idpID)
		}
		return idpMap[idpID], nil
	}
}
