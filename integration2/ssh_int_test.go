package ssh

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

func TestSSH(t *testing.T) {
	clientKey := newSSHKey(t)
	serverHostKey := newSSHKey(t)
	userCAKey := newSSHKey(t)

	// ssh client setup
	var ki scenarios.EmptyKeyboardInteractiveChallenge
	clientConfig := &ssh.ClientConfig{
		User: "demo@example",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(newSignerFromKey(t, clientKey)),
			ssh.KeyboardInteractive(ki.Do),
		},
		HostKeyCallback: ssh.FixedHostKey(newPublicKey(t, serverHostKey.Public())),
	}

	// pomerium + upstream setup
	env := testenv.New(t)

	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "test@example.com"}}, scenarios.WithEnableDeviceAuth(true)))
	env.Add(scenarios.SSH(scenarios.SSHConfig{
		HostKeys:  []any{serverHostKey},
		UserCAKey: userCAKey,
	}))
	env.Add(&ki)

	userCAPublicKey := newPublicKey(t, userCAKey.Public())
	certChecker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(userCAPublicKey.Marshal(), auth.Marshal())
		},
	}
	up := upstreams.SSH(
		upstreams.WithHostKeys(newSignerFromKey(t, serverHostKey)),
		upstreams.WithPublicKeyCallback(certChecker.Authenticate),
	)
	up.SetServerConnCallback(echoShell{t}.handleConnection)
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
	sess.Stdin = strings.NewReader("hello world\r")
	require.NoError(t, sess.Shell())
	require.NoError(t, sess.Wait())

	assert.Equal(t, "> hello world\r\nhello world\r\n> ", b.String())
}

type echoShell struct {
	t *testing.T
}

func (sh echoShell) handleConnection(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	var wg sync.WaitGroup
	defer wg.Wait()

	// Reject any global requests from the client.
	wg.Add(1)
	go func() {
		ssh.DiscardRequests(reqs)
		wg.Done()
	}()

	// Accept shell session requests.
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		require.NoError(sh.t, err, "echoShell: couldn't accept channel")

		// Acknowledge a 'shell' request.
		wg.Add(1)
		go func(in <-chan *ssh.Request) {
			for req := range in {
				req.Reply(req.Type == "shell", nil)
			}
			wg.Done()
		}(requests)

		// Simulate a terminal that echoes all input lines.
		term := term.NewTerminal(channel, "> ")

		wg.Add(1)
		go func() {
			defer func() {
				channel.Close()
				wg.Done()
			}()
			for {
				line, err := term.ReadLine()
				if errors.Is(err, io.EOF) {
					break
				}
				require.NoError(sh.t, err, "echoShell: couldn't read line")
				reply := append([]byte(line), '\n')
				_, err = term.Write(reply)
				require.NoError(sh.t, err, "echoShell: couldn't write line")
			}
			channel.SendRequest("exit-status", false, make([]byte, 4) /* uint32 0 */)
		}()
	}
}

// newSSHKey generates a new Ed25519 ssh key.
func newSSHKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return priv
}

// newSignerFromKey is a wrapper around ssh.NewSignerFromKey that will fail on error.
func newSignerFromKey(t *testing.T, key any) ssh.Signer {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

// newPublicKey is a wrapper around ssh.NewPublicKey that will fail on error.
func newPublicKey(t *testing.T, key any) ssh.PublicKey {
	t.Helper()
	sshkey, err := ssh.NewPublicKey(key)
	require.NoError(t, err)
	return sshkey
}
