package ssh

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

func TestSSH(t *testing.T) {
	clientKey := newSSHKey(t)
	serverHostKey := newSSHKey(t)

	// ssh client setup
	var ki scenarios.EmptyKeyboardInteractiveChallenge
	clientConfig := &ssh.ClientConfig{
		User: "demo@example",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(clientKey),
			ssh.KeyboardInteractive(ki.Do),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// pomerium + upstream setup
	env := testenv.New(t)

	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "test@example.com"}}, scenarios.WithEnableDeviceAuth(true)))
	env.Add(scenarios.SSH(scenarios.SSHConfig{}))
	env.Add(&ki)

	up := upstreams.SSH(
		upstreams.WithHostKeys(serverHostKey),
		upstreams.WithAuthorizedKey(clientKey.PublicKey(), "demo"),
		upstreams.WithBannerCallback(func(_ ssh.ConnMetadata) string {
			return "TEST BANNER"
		}))
	r := up.Route().
		From(env.SubdomainURLWithScheme("example", "ssh")).
		Policy(func(p *config.Policy) { p.AllowAnyAuthenticatedUser = true })
	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	// verify that a connection can be established
	client, err := up.Dial(r, clientConfig)
	require.NoError(t, err)
	defer client.Close()

	sess, err := client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	var b bytes.Buffer
	sess.Stdout = &b
	sess.Stdin = strings.NewReader("")
	sess.Shell()
	sess.Wait()

	assert.Equal(t, "TEST BANNER", b.String())
}

// newSSHKey generates and returns a new Ed25519 ssh key.
func newSSHKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer
}
