package scenarios

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/crypto/ssh"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/pkg/slices"
)

type SSHConfig struct {
	// Host key(s). An Ed25519 key will be generated if not set.
	// Elements must be of a type supported by [ssh.NewSignerFromKey].
	HostKeys []any

	// User CA key, for signing SSH certificates used to authenticate to an
	// upstream. An Ed25519 key will be generated if not set.
	// Must be a type supported by [ssh.NewSignerFromKey].
	UserCAKey any

	// If true, enables the 'ssh_allow_direct_tcpip' runtime flag
	EnableDirectTcpip bool

	// If true, enables the 'ssh_routes_portal' runtime flag
	EnableRoutesPortal bool
}

func SSH(c SSHConfig) testenv.Modifier {
	return testenv.ModifierFunc(func(ctx context.Context, cfg *config.Config) {
		env := testenv.EnvFromContext(ctx)

		if len(c.HostKeys) == 0 {
			c.HostKeys = []any{newEd25519Key(env)}
		}

		if c.UserCAKey == nil {
			c.UserCAKey = newEd25519Key(env)
		}

		marshalPrivateKey := func(key any) string {
			p, err := ssh.MarshalPrivateKey(key.(crypto.PrivateKey), "")
			env.Require().NoError(err)
			return string(pem.EncodeToMemory(p))
		}
		configHostKeys := slices.Map(c.HostKeys, marshalPrivateKey)
		cfg.Options.SSHHostKeys = &configHostKeys
		cfg.Options.SSHUserCAKey = marshalPrivateKey(c.UserCAKey)
		cfg.Options.RuntimeFlags[config.RuntimeFlagSSHAllowDirectTcpip] = c.EnableDirectTcpip
		cfg.Options.RuntimeFlags[config.RuntimeFlagSSHRoutesPortal] = c.EnableRoutesPortal
	})
}

func newEd25519Key(env testenv.Environment) ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(nil)
	env.Require().NoError(err)
	return priv
}

// EmptyKeyboardInteractiveChallenge responds to any keyboard-interactive
// challenges with zero prompts, and fails otherwise.
type EmptyKeyboardInteractiveChallenge struct {
	testenv.DefaultAttach
}

func (c *EmptyKeyboardInteractiveChallenge) Do(
	_, _ string, questions []string, _ []bool,
) (answers []string, err error) {
	if len(questions) > 0 {
		c.Env().Require().FailNow("unsupported keyboard-interactive challenge")
	}
	return nil, nil
}

type CodeExtractorInteractiveChallenge struct {
	certPool *x509.CertPool
}

func NewCodeExtractorChallenge(certPool *x509.CertPool) *CodeExtractorInteractiveChallenge {
	return &CodeExtractorInteractiveChallenge{
		certPool: certPool,
	}
}

func (c *CodeExtractorInteractiveChallenge) Do(ctx context.Context, codeURI string, email string) (answers []string, err error) {
	requestOpts := &upstreams.RequestOptions{}
	upstreams.AuthenticateAs(email)(requestOpts)
	client := upstreams.NewHTTPClient(
		c.certPool,
		requestOpts,
	)

	resp, err := upstreams.DoAuthenticatedRequest(
		ctx,
		func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodPost, codeURI, nil)
		},
		func(_ context.Context) *http.Client {
			return client
		},
		requestOpts,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response from code get: %s", resp.Status)
	}

	formData := url.Values{}
	formData.Add("confirm", "true")

	formResp, err := upstreams.DoAuthenticatedRequest(
		ctx,
		func(ctx context.Context) (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, codeURI, bytes.NewBufferString(formData.Encode()))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return req, nil
		},
		func(_ context.Context) *http.Client {
			return client
		},
		&upstreams.RequestOptions{},
	)
	if err != nil {
		return nil, err
	}
	defer formResp.Body.Close()
	if formResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response from code get: %s", resp.Status)
	}
	return nil, nil
}
