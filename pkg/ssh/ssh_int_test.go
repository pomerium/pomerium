package ssh_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	envoy_service_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/ratelimit"
)

//go:generate go tool go.uber.org/mock/mockgen -package ssh_test -destination ratelimit_mock_test.go github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3 RateLimitServiceServer

type SSHTestSuiteOptions struct {
	PPL        string
	UseCertKey bool
}

type SSHTestSuite struct {
	suite.Suite
	SSHTestSuiteOptions

	SSHKeys

	// These fields stay the same for the entire test suite
	template     *template.Template
	templateData TemplateData

	// These fields are recreated for each test in the suite
	env testenv.Environment
	// ClientConfig SSH client configuration for connections
	clientConfig *gossh.ClientConfig
}

type TemplateData struct {
	Email                string
	Username             string
	PublicKey            string
	PublicKeyFingerprint string
	SSHCa                string
}

func (s *SSHTestSuite) SetupSuite() {
	s.SSHKeys = NewSSHKeys(s.T())

	s.template = template.New("ppl").
		Funcs(template.FuncMap{
			"randomPublicKey": func() string {
				k := newSSHKey(s.T())
				sshKey, err := gossh.NewPublicKey(k.Public())
				s.Require().NoError(err)
				return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshKey)))
			},
			"quoteMeta": regexp.QuoteMeta,
		})
	s.templateData = TemplateData{
		Email:                "fake.user@example.com",
		Username:             "demo",
		PublicKey:            strings.TrimSpace(string(gossh.MarshalAuthorizedKey(s.ClientSSHPubKey))),
		PublicKeyFingerprint: gossh.FingerprintSHA256(s.ClientSSHPubKey),
		SSHCa:                strings.TrimSpace(string(gossh.MarshalAuthorizedKey(s.ClientCASshPubKey))),
	}

	s.PPL = s.executeTemplate(s.PPL)
}

func (s *SSHTestSuite) SetupTest() {
	s.env = testenv.New(s.T())

	var publicKeys []gossh.Signer
	if s.UseCertKey {
		caSigner, err := gossh.NewSignerFromKey(s.ClientCAKey)
		s.Require().NoError(err)
		cert := &gossh.Certificate{
			CertType:    gossh.UserCert,
			Key:         s.ClientSSHPubKey,
			ValidAfter:  uint64(time.Now().Add(-1 * time.Minute).Unix()),
			ValidBefore: uint64(time.Now().Add(1 * time.Hour).Unix()),
		}
		cert.SignCert(rand.Reader, caSigner)

		certSigner, err := gossh.NewCertSigner(cert, newSignerFromKey(s.T(), s.ClientKey))
		s.Require().NoError(err)
		publicKeys = append(publicKeys, certSigner)
	} else {
		publicKeys = []gossh.Signer{newSignerFromKey(s.T(), s.ClientKey)}
	}
	user := "fake.user@example.com"
	ki := scenarios.NewCodeExtractorChallenge(user)
	s.clientConfig = &gossh.ClientConfig{
		User: "demo@example",
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(publicKeys...),
			gossh.KeyboardInteractive(ki.Do),
		},
		HostKeyCallback: gossh.FixedHostKey(newPublicKey(s.T(), s.ServerHostKey.Public())),
	}
	s.env.Add(scenarios.NewIDP([]*scenarios.User{{Email: user}}))
	s.env.Add(scenarios.SSH(scenarios.SSHConfig{
		HostKeys:           []any{s.ServerHostKey},
		UserCAKey:          s.UserCAKey,
		EnableDirectTcpip:  true,
		EnableRoutesPortal: true,
	}))
	s.env.Add(ki)
}

func (s *SSHTestSuite) TearDownTest() {
	s.env.Stop()
}

func (s *SSHTestSuite) executeTemplate(input string) string {
	var out bytes.Buffer
	tmpl, err := s.template.Parse(input)
	s.Require().NoError(err, "invalid template input")
	err = tmpl.Execute(&out, s.templateData)
	s.Require().NoError(err, "failed to execute template")
	return out.String()
}

func (s *SSHTestSuite) start() {
	s.env.Start()
	snippets.WaitStartupComplete(s.env)
}

func (s *SSHTestSuite) TestNormalSession() {
	userCAPublicKey := newPublicKey(s.T(), s.UserCAKey.Public())
	certChecker := gossh.CertChecker{
		IsUserAuthority: func(auth gossh.PublicKey) bool {
			return bytes.Equal(userCAPublicKey.Marshal(), auth.Marshal())
		},
	}
	upstream := upstreams.SSH(
		upstreams.WithHostKeys(newSignerFromKey(s.T(), s.UpstreamHostKey)),
		upstreams.WithPublicKeyCallback(certChecker.Authenticate),
	)
	upstream.SetServerConnCallback(echoShell{s.T()}.handleConnection)
	upstream.Route().
		From(values.Const("ssh://example")).
		PPL(s.PPL)
	s.env.AddUpstream(upstream)

	s.start()

	client, err := upstream.Dial(s.clientConfig)
	s.Require().NoError(err)
	defer client.Close()

	VerifyWorkingShell(s.T(), client)
}

func (s *SSHTestSuite) TestReevaluatePolicyOnConfigChange() {
	userCAPublicKey := newPublicKey(s.T(), s.UserCAKey.Public())
	certChecker := gossh.CertChecker{
		IsUserAuthority: func(auth gossh.PublicKey) bool {
			return bytes.Equal(userCAPublicKey.Marshal(), auth.Marshal())
		},
	}
	upstream := upstreams.SSH(
		upstreams.WithHostKeys(newSignerFromKey(s.T(), s.UpstreamHostKey)),
		upstreams.WithPublicKeyCallback(certChecker.Authenticate),
	)
	upstream.SetServerConnCallback(echoShell{s.T()}.handleConnection)
	upstream.Route().
		From(values.Const("ssh://example")).
		PPL(s.PPL)
	s.env.AddUpstream(upstream)

	s.start()

	client, err := upstream.Dial(s.clientConfig)
	s.Require().NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	s.Require().NoError(err)
	// make sure stdin blocks, otherwise the session will send an EOF message which
	// interferes with the test
	var w io.WriteCloser
	sess.Stdin, w = io.Pipe()
	s.T().Cleanup(func() {
		w.Close()
	})
	err = sess.Shell()
	s.Require().NoError(err)

	s.env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		for i, policy := range cfg.Options.GetAllPoliciesIndexed() {
			if policy.IsSSH() {
				for j, rule := range cfg.Options.Policies[i].Policy.Rules {
					rule.Or, rule.Nor = rule.Nor, rule.Or
					rule.And, rule.Not = rule.Not, rule.And
					cfg.Options.Policies[i].Policy.Rules[j] = rule
				}
			}
		}
	}))

	sess.Wait()
	s.ErrorContains(client.Wait(), "ssh: disconnect, reason 2: Permission Denied: access denied{via_upstream}")
}

func (s *SSHTestSuite) TestRevokeSession() {
	userCAPublicKey := newPublicKey(s.T(), s.UserCAKey.Public())
	certChecker := gossh.CertChecker{
		IsUserAuthority: func(auth gossh.PublicKey) bool {
			return bytes.Equal(userCAPublicKey.Marshal(), auth.Marshal())
		},
	}
	upstream := upstreams.SSH(
		upstreams.WithHostKeys(newSignerFromKey(s.T(), s.UpstreamHostKey)),
		upstreams.WithPublicKeyCallback(certChecker.Authenticate),
	)
	upstream.SetServerConnCallback(echoShell{s.T()}.handleConnection)
	upstream.Route().
		From(values.Const("ssh://example")).
		PPL(s.PPL)
	s.env.AddUpstream(upstream)

	s.start()
	dbClient := s.env.NewDataBrokerServiceClient()

	client, err := upstream.Dial(s.clientConfig)
	s.Require().NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	s.Require().NoError(err)

	_, err = dbClient.Put(s.env.Context(), &databroker.PutRequest{
		Records: []*databroker.Record{
			{
				Type:       "type.googleapis.com/session.SessionBinding",
				Id:         "sshkey-" + gossh.FingerprintSHA256(s.ClientSSHPubKey),
				ModifiedAt: timestamppb.Now(),
				DeletedAt:  timestamppb.Now(),
			},
		},
	})
	s.Require().NoError(err)
	sess.Wait()
	s.ErrorContains(client.Wait(), "ssh: disconnect, reason 2: Permission Denied: no longer authorized{via_upstream}")
}

func (s *SSHTestSuite) TestDirectTcpipSession() {
	upstream := upstreams.SSH(
		upstreams.WithHostKeys(newSignerFromKey(s.T(), s.UpstreamHostKey)),
		upstreams.WithAuthorizedKey(s.ClientSSHPubKey, "demo"),
	)
	upstream.SetServerConnCallback(echoShell{s.T()}.handleConnection)
	upstream.Route().
		From(values.Const("ssh://example")).
		PPL(s.PPL)
	s.env.AddUpstream(upstream)

	s.start()

	s.clientConfig.User = "demo"
	client, err := upstream.Dial(s.clientConfig)
	s.Require().NoError(err)
	defer client.Close()

	direct := ssh.ChannelOpenDirectMsg{
		DestAddr: "example",
		SrcAddr:  "127.0.0.1",
	}
	channel, requestsC, err := client.OpenChannel("direct-tcpip", gossh.Marshal(direct))
	s.Require().NoError(err)
	go gossh.DiscardRequests(requestsC)
	defer channel.Close()

	clientConn, newChannel, requests, err := gossh.NewClientConn(upstreams.NewRWConn(channel, channel), "", &gossh.ClientConfig{
		User: "demo",
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(newSignerFromKey(s.T(), s.ClientKey)),
		},
		HostKeyCallback: gossh.FixedHostKey(newPublicKey(s.T(), s.UpstreamHostKey.Public())),
	})
	s.Require().NoError(err)
	directClient := gossh.NewClient(clientConn, newChannel, requests)

	VerifyWorkingShell(s.T(), directClient)
}

func (s *SSHTestSuite) TestLoginLogout() {
	upstream := upstreams.SSH()
	upstream.Route().
		From(values.Const("ssh://example")).
		PPL(s.PPL)
	s.env.AddUpstream(upstream)

	s.start()

	s.clientConfig.User = "demo"
	client, err := upstream.Dial(s.clientConfig)
	s.Require().NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	s.Require().NoError(err)
	defer sess.Close()

	output, err := sess.CombinedOutput("logout")
	s.Require().NoError(err)
	s.Equal("Logged out successfully\n", string(output))
}

func (s *SSHTestSuite) TestWhoami() {
	upstream := upstreams.SSH()
	upstream.Route().
		From(values.Const("ssh://example")).
		PPL(s.PPL)
	s.env.AddUpstream(upstream)

	s.start()

	s.clientConfig.User = "demo"
	client, err := upstream.Dial(s.clientConfig)
	s.Require().NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	s.Require().NoError(err)
	defer sess.Close()

	output, err := sess.CombinedOutput("whoami")
	s.Require().NoError(err)
	s.Regexp(s.executeTemplate(`
User ID:    .*
Session ID: .+
Expires at: .* \(in \d+h\d+m\d+s\)
Claims:
  aud: "CLIENT_ID"
  email: "{{.Email | quoteMeta}}"
  exp: .* \(in \d+h\d+m\d+s\)
  family_name: ""
  given_name: ""
  iat: .* \(\d+s ago\)
  iss: "https://mock-idp\..*"
  name: ""
  sub: ".*"
`[1:]), string(output))
}

func TestSSH(t *testing.T) {
	for i, opts := range []SSHTestSuiteOptions{
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
    - ssh_ca: ["{{.SSHCa}}"]
    - ssh_username:
        in: ["someotherusername", "{{.Username}}"]
`,
			UseCertKey: true,
		},
	} {
		ok := t.Run("", func(t *testing.T) {
			suite.Run(t, &SSHTestSuite{
				SSHTestSuiteOptions: opts,
			})
		})
		require.Truef(t, ok, "case %d failed", i)
	}
}

type echoShell struct {
	t *testing.T
}

func (sh echoShell) handleConnection(_ *gossh.ServerConn, chans <-chan gossh.NewChannel, reqs <-chan *gossh.Request) {
	var wg sync.WaitGroup
	defer wg.Wait()

	// Reject any global requests from the client.
	wg.Add(1)
	go func() {
		gossh.DiscardRequests(reqs)
		wg.Done()
	}()

	// Accept shell session requests.
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(gossh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		require.NoError(sh.t, err, "echoShell: couldn't accept channel")

		// Acknowledge a 'shell' request.
		wg.Add(1)
		go func(in <-chan *gossh.Request) {
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

func TestSSHRateLimit(t *testing.T) {
	ctrl := gomock.NewController(t)
	rls := NewMockRateLimitServiceServer(ctrl)
	rls.EXPECT().ShouldRateLimit(gomock.Any(), gomock.Any()).Times(1).DoAndReturn(
		func(_ context.Context, req *envoy_service_ratelimit_v3.RateLimitRequest) (*envoy_service_ratelimit_v3.RateLimitResponse, error) {
			return &envoy_service_ratelimit_v3.RateLimitResponse{
				OverallCode: envoy_service_ratelimit_v3.RateLimitResponse_OK,
				Statuses:    ratelimit.MakeResponse(envoy_service_ratelimit_v3.RateLimitResponse_OK, len(req.Descriptors)),
			}, nil
		},
	)
	rls.EXPECT().ShouldRateLimit(gomock.Any(), gomock.Any()).Times(1).DoAndReturn(
		func(_ context.Context, req *envoy_service_ratelimit_v3.RateLimitRequest) (*envoy_service_ratelimit_v3.RateLimitResponse, error) {
			return &envoy_service_ratelimit_v3.RateLimitResponse{
				OverallCode: envoy_service_ratelimit_v3.RateLimitResponse_OVER_LIMIT,
				Statuses:    ratelimit.MakeResponse(envoy_service_ratelimit_v3.RateLimitResponse_OVER_LIMIT, len(req.Descriptors)),
			}, nil
		},
	)

	env := testenv.New(t)
	env.AddOption(pomerium.WithAuthorizeServerOptions(
		authorize.WithRateLimitServer(rls),
	))

	keys := NewSSHKeys(t)
	publicKeys := []gossh.Signer{newSignerFromKey(t, keys.ClientKey)}
	user := "fake.user@example.com"
	ki := scenarios.NewCodeExtractorChallenge(user)
	clientConfig := &gossh.ClientConfig{
		User: "demo@example",
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(publicKeys...),
			gossh.KeyboardInteractive(ki.Do),
		},
		HostKeyCallback: gossh.FixedHostKey(newPublicKey(t, keys.ServerHostKey.Public())),
	}
	env.Add(ki)
	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: user}}))
	env.Add(scenarios.SSH(scenarios.SSHConfig{
		HostKeys:           []any{keys.ServerHostKey},
		UserCAKey:          keys.UserCAKey,
		EnableDirectTcpip:  true,
		EnableRoutesPortal: true,
	}))
	t.Cleanup(func() {
		env.Stop()
	})

	userCAPublicKey := newPublicKey(t, keys.UserCAKey.Public())
	certChecker := gossh.CertChecker{
		IsUserAuthority: func(auth gossh.PublicKey) bool {
			return bytes.Equal(userCAPublicKey.Marshal(), auth.Marshal())
		},
	}
	upstream := upstreams.SSH(
		upstreams.WithHostKeys(newSignerFromKey(t, keys.UpstreamHostKey)),
		upstreams.WithPublicKeyCallback(certChecker.Authenticate),
	)
	upstream.SetServerConnCallback(echoShell{t}.handleConnection)
	upstream.Route().
		From(values.Const("ssh://example")).
		PPL(`{"allow":{"and":[{"authenticated_user":"fake.user@example.com"}]}}`)
	env.AddUpstream(upstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	client1, err := upstream.Dial(clientConfig)
	require.NoError(t, err)
	defer client1.Close()

	VerifyWorkingShell(t, client1)

	_, err = upstream.Dial(clientConfig)
	require.Error(t, err)
	require.ErrorContains(t, err, "handshake failed")
}
