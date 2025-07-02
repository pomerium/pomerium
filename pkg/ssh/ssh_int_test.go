package ssh_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
)

type SSHTestSuiteOptions struct {
	PPL        string
	UseCertKey bool
}

type SSHTestSuite struct {
	suite.Suite
	SSHTestSuiteOptions

	env testenv.Environment

	clientKey         ed25519.PrivateKey
	clientSshPubKey   ssh.PublicKey
	serverHostKey     ed25519.PrivateKey
	userCAKey         ed25519.PrivateKey
	clientCAKey       ed25519.PrivateKey
	clientCASshPubKey ssh.PublicKey

	clientConfig *ssh.ClientConfig

	upstream upstreams.SSHUpstream
}

type PPLTemplateData struct {
	Email     string
	Username  string
	PublicKey string
	SshCa     string
}

func (s *SSHTestSuite) SetupTest() {
	s.env = testenv.New(s.T())
	s.clientKey = newSSHKey(s.T())
	s.serverHostKey = newSSHKey(s.T())
	s.userCAKey = newSSHKey(s.T())
	s.clientCAKey = newSSHKey(s.T())
	var err error
	s.clientSshPubKey, err = ssh.NewPublicKey(s.clientKey.Public())
	s.Require().NoError(err)
	s.clientCASshPubKey, err = ssh.NewPublicKey(s.clientCAKey.Public())
	s.Require().NoError(err)

	var publicKeys []ssh.Signer
	if s.UseCertKey {
		caSigner, err := ssh.NewSignerFromKey(s.clientCAKey)
		s.Require().NoError(err)
		cert := &ssh.Certificate{
			CertType:    ssh.UserCert,
			Key:         s.clientSshPubKey,
			ValidAfter:  uint64(time.Now().Add(-1 * time.Minute).Unix()),
			ValidBefore: uint64(time.Now().Add(1 * time.Hour).Unix()),
		}
		cert.SignCert(rand.Reader, caSigner)

		certSigner, err := ssh.NewCertSigner(cert, newSignerFromKey(s.T(), s.clientKey))
		s.Require().NoError(err)
		publicKeys = append(publicKeys, certSigner)
	} else {
		publicKeys = []ssh.Signer{newSignerFromKey(s.T(), s.clientKey)}
	}
	var ki scenarios.EmptyKeyboardInteractiveChallenge
	s.clientConfig = &ssh.ClientConfig{
		User: "demo@example",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(publicKeys...),
			ssh.KeyboardInteractive(ki.Do),
		},
		HostKeyCallback: ssh.FixedHostKey(newPublicKey(s.T(), s.serverHostKey.Public())),
	}
	// ssh client setup
	s.env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "fake.user@example.com"}}, scenarios.WithEnableDeviceAuth(true)))
	s.env.Add(scenarios.SSH(scenarios.SSHConfig{
		HostKeys:  []any{s.serverHostKey},
		UserCAKey: s.userCAKey,
	}))
	s.env.Add(&ki)

	userCAPublicKey := newPublicKey(s.T(), s.userCAKey.Public())
	certChecker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(userCAPublicKey.Marshal(), auth.Marshal())
		},
	}
	s.upstream = upstreams.SSH(
		upstreams.WithHostKeys(newSignerFromKey(s.T(), s.serverHostKey)),
		upstreams.WithPublicKeyCallback(certChecker.Authenticate),
	)

	var ppl bytes.Buffer
	s.Require().NoError(
		template.Must(
			template.New("ppl").
				Funcs(template.FuncMap{
					"randomPublicKey": func() string {
						k := newSSHKey(s.T())
						sshKey, err := ssh.NewPublicKey(k.Public())
						s.Require().NoError(err)
						return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshKey)))
					},
				}).
				Parse(s.PPL)).
			Execute(&ppl, PPLTemplateData{
				Email:     "fake.user@example.com",
				Username:  "demo",
				PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.clientSshPubKey))),
				SshCa:     strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.clientCASshPubKey))),
			}))
	s.upstream.Route().
		From(values.Const("ssh://example")).
		PPL(ppl.String())
}

func (s *SSHTestSuite) start() {
	s.env.AddUpstream(s.upstream)
	s.env.Start()
	snippets.WaitStartupComplete(s.env)
}

func (s *SSHTestSuite) TearDownTest() {
	s.env.Stop()
}

func (s *SSHTestSuite) TestShell() {
	s.upstream.SetServerConnCallback(echoShell{s.T()}.handleConnection)

	s.start()

	// verify that a connection can be established
	client, err := s.upstream.Dial(s.clientConfig)
	s.Require().NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	s.Require().NoError(err)
	defer sess.Close()

	var b bytes.Buffer
	sess.Stdout = &b
	sess.Stdin = strings.NewReader("hello world\r")
	s.Require().NoError(sess.Shell())
	s.Require().NoError(sess.Wait())

	s.Equal("> hello world\r\nhello world\r\n> ", b.String())
}

func TestSSH(t *testing.T) {
	for _, opts := range []SSHTestSuiteOptions{
		0: {PPL: `{"allow":{"and":[{"authenticated_user":1}]}}`},
		1: {PPL: `{"allow":{"and":[{"email":{"is":"{{.Email}}"}}]}}`},
		2: {PPL: `
allow:
  and:
    - email:
        is: "{{.Email}}"
    - ssh_publickey: "{{.PublicKey}}"
`},
		3: {PPL: `
allow:
  and:
    - email:
        is: "{{.Email}}"
    - ssh_publickey: "{{.PublicKey}}"
    - ssh_username: "{{.Username}}"
`},
		4: {PPL: `
allow:
  and:
    - email:
        is: "{{.Email}}"
    - ssh_publickey: ["{{randomPublicKey}}", "{{.PublicKey}}"]
    - ssh_username:
        in: ["someotherusername", "{{.Username}}"]
`},
		5: {
			PPL: `
allow:
  and:
    - email:
        is: "{{.Email}}"
    - ssh_ca: ["{{.SshCa}}"]
    - ssh_username:
        in: ["someotherusername", "{{.Username}}"]
`,
			UseCertKey: true,
		},
	} {
		t.Run("", func(t *testing.T) {
			suite.Run(t, &SSHTestSuite{
				SSHTestSuiteOptions: opts,
			})
		})
	}
}

func TestSSH_DirectTcpip(t *testing.T) {
}

func TestSSH_RoutesPortal(t *testing.T) {
}

func TestSSH_Exec(t *testing.T) {
}

func TestSSH_ReevaluatePolicyOnConfigChange(t *testing.T) {
}

type echoShell struct {
	t *testing.T
}

func (sh echoShell) handleConnection(_ *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
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
