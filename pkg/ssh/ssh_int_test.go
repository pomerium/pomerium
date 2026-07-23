package ssh_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
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
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/ratelimit"
)

//go:generate go tool go.uber.org/mock/mockgen -package ssh_test -destination ratelimit_mock_test.go github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3 RateLimitServiceServer

type PublicKeyType int

const (
	Regular PublicKeyType = iota // regular non-cert ssh key
	CertKey                      // cert key
)

type IdpUserOptions struct {
	mockidp.User
	PublicKeyType PublicKeyType // The public key used when logging in as this user
}

type RouteOptions struct {
	Name        string // without ssh:// prefix
	PPLTemplate string
	EditPolicy  func(*config.Policy) // after setting PPL
}

type IdpUser struct {
	IdpUserOptions

	SSHKey gossh.Signer
}

type SSHTestSuiteOptions struct {
	// Routes   []RouteOptions
	IdpUsers []IdpUserOptions
}

type SSHTestSuite struct {
	suite.Suite
	Opts SSHTestSuiteOptions

	// These fields stay the same for the entire test suite
	SSHKeys
	template *template.Template
	idpUsers []*IdpUser

	// These fields are recreated for each test in the suite
	env                   testenv.Environment
	challengeImpl         *scenarios.CodeExtractorInteractiveChallenge
	upstream              upstreams.SSHUpstream
	clientConfigUsersSeen map[string]struct{}
}

func (s *SSHTestSuite) SetupSuite() {
	s.SSHKeys = NewSSHKeys(s.T())

	s.idpUsers = []*IdpUser{}

	for _, user := range s.Opts.IdpUsers {
		s.idpUsers = append(s.idpUsers, s.newUser(user))
	}

	s.template = template.New("ppl").
		Funcs(template.FuncMap{
			"userPublicKey": func(email string) string {
				for _, user := range s.idpUsers {
					if user.Email == email {
						return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(user.SSHKey.PublicKey())))
					}
				}
				return "<error>"
			},
			"quoteMeta": regexp.QuoteMeta,
		})
}

func (s *SSHTestSuite) newUser(opts IdpUserOptions) *IdpUser {
	sshKey := newSignerFromKey(s.T(), newSSHKey(s.T()))

	switch opts.PublicKeyType {
	case Regular:
		return &IdpUser{
			IdpUserOptions: opts,
			SSHKey:         sshKey,
		}
	case CertKey:
		caSigner, err := gossh.NewSignerFromKey(s.ClientCAKey)
		s.Require().NoError(err)
		cert := &gossh.Certificate{
			CertType:    gossh.UserCert,
			Key:         sshKey.PublicKey(),
			ValidAfter:  uint64(time.Now().Add(-1 * time.Minute).Unix()),
			ValidBefore: uint64(time.Now().Add(1 * time.Hour).Unix()),
		}
		cert.SignCert(rand.Reader, caSigner)

		certKey, err := gossh.NewCertSigner(cert, sshKey)
		s.Require().NoError(err)
		return &IdpUser{
			IdpUserOptions: opts,
			SSHKey:         certKey,
		}
	default:
		panic("invalid public key type")
	}
}

func (s *SSHTestSuite) SetupTest() {
	s.env = testenv.New(s.T())
	s.challengeImpl = scenarios.NewCodeExtractorChallenge(s.env.ServerCAs())

	mockidpUsers := []*mockidp.User{}
	for _, user := range s.idpUsers {
		mockidpUsers = append(mockidpUsers, &user.User)
	}

	s.env.Add(scenarios.NewIDP(mockidpUsers))
}

func (s *SSHTestSuite) TearDownTest() {
	log.Ctx(s.env.Context()).Info().Msg("==== begin test teardown ====")
	defer log.Ctx(s.env.Context()).Info().Msg("==== end test teardown ====")
	s.env.Stop()
}

func (s *SSHTestSuite) executeTemplate(input string) string {
	var out bytes.Buffer
	tmpl, err := s.template.Parse(input)
	s.Require().NoError(err, "invalid template input")
	err = tmpl.Execute(&out, struct{}{})
	s.Require().NoError(err, "failed to execute template")
	return out.String()
}

type startOptions struct {
	upstreamOpts       []upstreams.SSHUpstreamOption
	enableDirectTcpip  bool
	enableRoutesPortal bool
}

type startOption func(*startOptions)

func (o *startOptions) apply(opts ...startOption) {
	for _, op := range opts {
		op(o)
	}
}

func WithSSHUpstreamOptions(upstreamOpts ...upstreams.SSHUpstreamOption) startOption {
	return func(o *startOptions) {
		o.upstreamOpts = upstreamOpts
	}
}

func WithEnableDirectTcpip(enable bool) startOption {
	return func(o *startOptions) {
		o.enableDirectTcpip = enable
	}
}

func WithEnableRoutesPortal(enable bool) startOption {
	return func(o *startOptions) {
		o.enableRoutesPortal = enable
	}
}

func (s *SSHTestSuite) start(routes []RouteOptions, startOpts ...startOption) {
	opts := startOptions{
		enableDirectTcpip:  true,
		enableRoutesPortal: true,
	}
	opts.apply(startOpts...)

	s.env.Add(scenarios.SSH(scenarios.SSHConfig{
		HostKeys:           []any{s.ServerHostKey},
		UserCAKey:          s.UserCAKey,
		EnableDirectTcpip:  opts.enableDirectTcpip,
		EnableRoutesPortal: opts.enableRoutesPortal,
	}))

	// Set up routes
	userCAPublicKey := newPublicKey(s.T(), s.UserCAKey.Public())
	certChecker := gossh.CertChecker{
		IsUserAuthority: func(auth gossh.PublicKey) bool {
			return bytes.Equal(userCAPublicKey.Marshal(), auth.Marshal())
		},
	}
	s.upstream = upstreams.SSH(append([]upstreams.SSHUpstreamOption{
		upstreams.WithHostKeys(newSignerFromKey(s.T(), s.UpstreamHostKey)),
		upstreams.WithPublicKeyCallback(certChecker.Authenticate),
	}, opts.upstreamOpts...)...)
	s.upstream.SetServerConnCallback(echoShell{s.T()}.handleConnection)
	for _, route := range routes {
		r := s.upstream.Route().
			From(values.Const("ssh://" + route.Name)).
			PPL(s.executeTemplate(route.PPLTemplate))
		if route.EditPolicy != nil {
			r.Policy(route.EditPolicy)
		}
	}
	s.env.AddUpstream(s.upstream)
	s.clientConfigUsersSeen = map[string]struct{}{}

	s.env.Start()
	snippets.WaitStartupComplete(s.env)
}

func (s *SSHTestSuite) lookupUser(userEmail string) *IdpUser {
	var user *IdpUser
	for _, u := range s.idpUsers {
		if u.Email == userEmail {
			user = u
			break
		}
	}
	s.Require().NotNilf(user, "test bug: no such user with email %s", userEmail)
	return user
}

func (s *SSHTestSuite) newClientConfig(loginName string, route string, userEmail string) *gossh.ClientConfig {
	s.Require().NotContains(s.clientConfigUsersSeen, userEmail,
		"test bug: do not call newClientConfig with the same user twice during the same test")
	user := s.lookupUser(userEmail)
	username := loginName
	if route != "" {
		username += "@" + route
	}
	return &gossh.ClientConfig{
		User: username,
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(user.SSHKey),
			gossh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) (answers []string, err error) {
				return s.challengeImpl.Do(s.env.Context(), instruction, user.Email)
			}),
		},
		HostKeyCallback: gossh.FixedHostKey(newPublicKey(s.T(), s.ServerHostKey.Public())),
	}
}

func expectAuthSequence(t *testing.T, cc *gossh.ClientConfig, attemptListeners []func(ctx *gossh.ClientAuthContext) gossh.AuthMethod) (verify func()) {
	cc.AuthCallback = func(ctx *gossh.ClientAuthContext) (gossh.AuthMethod, error) {
		t.Helper()
		require.NotEmptyf(t, attemptListeners, "too many auth sequence steps (context: %#v)", ctx)
		m := attemptListeners[0](ctx) // nil can be returned to use the previously configured methods
		attemptListeners = attemptListeners[1:]
		if t.Failed() {
			return nil, errors.New("(test failed)")
		}
		return m, nil
	}
	return func() {
		if !t.Failed() && len(attemptListeners) > 0 {
			t.Errorf("auth sequence completed too early, %d additional steps did not occur", len(attemptListeners))
		}
	}
}

func (s *SSHTestSuite) TestNormalSession() {
	s.start([]RouteOptions{
		{
			Name: "route1",
			PPLTemplate: `
allow:
  and:
    - email:
        in:
          - "user1@example.com"
`,
		},
		{
			Name: "route2",
			PPLTemplate: `
allow:
  and:
    - ssh_publickey:
        - "{{ userPublicKey "user3@example.com" }}"
    - email:
        in:
          - "user3@example.com"
`,
		},
		{
			Name: "route3",
			PPLTemplate: `
allow:
  and:
    - ssh_publickey:
      - "{{ userPublicKey "user5@example.com" }}"
      - "{{ userPublicKey "user6@example.com" }}"
      - "{{ userPublicKey "user7@example.com" }}"
      - "{{ userPublicKey "user8@example.com" }}"
    - email:
        in:
          - "user5@example.com"
          - "user7@example.com"
`,
		},
		{ // note: this policy is invalid, but that only becomes apparent after
			// successfully authenticating with a public key
			Name: "invalidroute1",
			PPLTemplate: `
allow:
  and:
    - ssh_publickey:
        - "{{ userPublicKey "user9@example.com" }}"
`,
		},
		{
			Name: "invalidroute2",
			EditPolicy: func(p *config.Policy) {
				p.AllowPublicUnauthenticatedAccess = true
			},
		},
	})

	seqPublicKeyAcceptedThenKbdInt := func(t *testing.T) []func(*gossh.ClientAuthContext) gossh.AuthMethod {
		return []func(ctx *gossh.ClientAuthContext) gossh.AuthMethod{
			func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
				t.Helper()
				s.Require().Equal([]string{"publickey"}, ctx.AllowedMethods)
				s.Require().Empty(ctx.PartialSuccessMethods)
				s.Require().Equal([]string{"none"}, ctx.TriedMethods)
				return nil
			},
			func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
				t.Helper()
				s.Require().Equal([]string{"keyboard-interactive"}, ctx.AllowedMethods)
				s.Require().Equal([]string{"publickey"}, ctx.PartialSuccessMethods)
				s.Require().Equal([]string{"none"}, ctx.TriedMethods)
				return nil
			},
		}
	}
	seqPublicKeyRejected := func(t *testing.T) []func(*gossh.ClientAuthContext) gossh.AuthMethod {
		return []func(ctx *gossh.ClientAuthContext) gossh.AuthMethod{
			func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
				t.Helper()
				s.Require().Equal([]string{"publickey"}, ctx.AllowedMethods)
				s.Require().Empty(ctx.PartialSuccessMethods)
				s.Require().Equal([]string{"none"}, ctx.TriedMethods)
				return nil
			},
			func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
				t.Helper()
				// second publickey attempt will fail (assuming only one configured key)
				s.Require().Equal([]string{"publickey"}, ctx.AllowedMethods)
				s.Require().Empty(ctx.PartialSuccessMethods)
				s.Require().Equal([]string{"none", "publickey"}, ctx.TriedMethods)
				return nil
			},
		}
	}

	// By default, when using the ssh.PublicKeys auth method with multiple keys,
	// if one of them is rejected then the ssh client will silently attempt the
	// others without going through the auth callback first. So we have to return
	// separate AuthMethod instances with one public key per attempt.
	//
	// Returning a non-nil AuthMethod from the callback overrides the configured
	// methods from the Auth field, so all the methods for the whole sequence
	// need to be passed in here.
	seqPublicKeyAcceptedAfter1RetryThenKbdInit := func(t *testing.T, keys [2]gossh.Signer, kbdInt gossh.AuthMethod) []func(*gossh.ClientAuthContext) gossh.AuthMethod {
		return []func(ctx *gossh.ClientAuthContext) gossh.AuthMethod{
			func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
				s.T().Helper()
				s.Require().Equal([]string{"publickey"}, ctx.AllowedMethods)
				s.Require().Empty(ctx.PartialSuccessMethods)
				s.Require().Equal([]string{"none"}, ctx.TriedMethods)
				return gossh.PublicKeys(keys[0])
			},
			func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
				s.T().Helper()
				s.Require().Equal([]string{"publickey"}, ctx.AllowedMethods)
				s.Require().Empty(ctx.PartialSuccessMethods)
				s.Require().Equal([]string{"none", "publickey"}, ctx.TriedMethods)
				return gossh.PublicKeys(keys[1])
			},
			func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
				s.T().Helper()
				s.Require().Equal([]string{"keyboard-interactive"}, ctx.AllowedMethods)
				s.Require().Equal([]string{"publickey"}, ctx.PartialSuccessMethods)
				s.Require().Equal([]string{"none", "publickey"}, ctx.TriedMethods)
				return kbdInt
			},
		}
	}

	// NB: use different users for each test, otherwise earlier tests can affect
	// later tests due to sessions/session bindings persisting. logout is not
	// sufficient here

	s.Run("route1", func() {
		s.Run("authorized via email", func() {
			cc := s.newClientConfig("username", "route1", "user1@example.com")
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
		s.Run("email unauthorized", func() {
			cc := s.newClientConfig("username", "route1", "user2@example.com")
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
	})

	s.Run("route2", func() {
		s.Run("authorized via email and public key", func() {
			cc := s.newClientConfig("username", "route2", "user3@example.com")
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
		s.Run("public key unauthorized", func() {
			cc := s.newClientConfig("username", "route2", "user4@example.com")
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyRejected(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")
		})
	})

	s.Run("route3", func() {
		s.Run("authorized via email and public key", func() {
			cc := s.newClientConfig("username", "route3", "user5@example.com")
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
		s.Run("public key matches criteria but email is unauthorized", func() {
			cc := s.newClientConfig("username", "route3", "user6@example.com")
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
		s.Run("public key accepted after retry", func() {
			randomKey := newSignerFromKey(s.T(), newSSHKey(s.T()))
			cc := s.newClientConfig("username", "route3", "user7@example.com")
			cc.Auth = nil
			verify := expectAuthSequence(s.T(), cc,
				seqPublicKeyAcceptedAfter1RetryThenKbdInit(s.T(),
					[2]gossh.Signer{randomKey, s.lookupUser("user7@example.com").SSHKey},
					gossh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) (answers []string, err error) {
						return s.challengeImpl.Do(s.env.Context(), instruction, "user7@example.com")
					})))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
		s.Run("public key accepted after retry but email is unauthorized", func() {
			randomKey := newSignerFromKey(s.T(), newSSHKey(s.T()))
			cc := s.newClientConfig("username", "route3", "user8@example.com")
			cc.Auth = nil
			verify := expectAuthSequence(s.T(), cc,
				seqPublicKeyAcceptedAfter1RetryThenKbdInit(s.T(),
					[2]gossh.Signer{randomKey, s.lookupUser("user8@example.com").SSHKey},
					gossh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) (answers []string, err error) {
						return s.challengeImpl.Do(s.env.Context(), instruction, "user8@example.com")
					})))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
	})

	s.Run("invalidroute1", func() {
		s.Run("public key unauthorized", func() {
			cc := s.newClientConfig("username", "invalidroute1", "user10@example.com")
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyRejected(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")
		})
		s.Run("public key accepted, but unauthorized due to missing session criteria", func() {
			cc := s.newClientConfig("username", "invalidroute1", "user9@example.com")
			verify := expectAuthSequence(s.T(), cc, []func(ctx *gossh.ClientAuthContext) gossh.AuthMethod{
				func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
					s.Require().Equal([]string{"publickey"}, ctx.AllowedMethods)
					s.Require().Empty(ctx.PartialSuccessMethods)
					s.Require().Equal([]string{"none"}, ctx.TriedMethods)
					return nil
				},
			})
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
	})

	s.Run("invalidroute2", func() {
		s.Run("unauthorized due to invalid route", func() {
			cc := s.newClientConfig("username", "invalidroute2", "user11@example.com")
			verify := expectAuthSequence(s.T(), cc, []func(ctx *gossh.ClientAuthContext) gossh.AuthMethod{
				func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
					s.T().Helper()
					s.Require().Equal([]string{"publickey"}, ctx.AllowedMethods)
					s.Require().Empty(ctx.PartialSuccessMethods)
					s.Require().Equal([]string{"none"}, ctx.TriedMethods)
					return nil
				},
			})
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
	})

	s.Run("internal cli", func() {
		cc := s.newClientConfig("username", "", "user12@example.com")
		verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
		defer verify()
		client, err := s.upstream.Dial(cc)
		s.Require().NoError(err)
		client.Close()
	})
}

func (s *SSHTestSuite) TestReevaluatePolicyOnConfigChange() {
	s.start([]RouteOptions{
		{
			Name: "route1",
			PPLTemplate: `
allow:
  and:
    - email:
        is: "user1@example.com"
`,
		},
	})

	client, err := s.upstream.Dial(s.newClientConfig("username", "route1", "user1@example.com"))
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
	err = client.Wait()
	s.ErrorContains(err, "ssh: disconnect, reason 2")
	s.ErrorContains(err, "Permission Denied: access denied{via_upstream}")
}

func (s *SSHTestSuite) TestRevokeSession() {
	s.start([]RouteOptions{
		{
			Name: "route1",
			PPLTemplate: `
allow:
  and:
    - email:
        is: "user1@example.com"
`,
		},
	})

	dbClient := s.env.NewDataBrokerServiceClient()
	user := s.lookupUser("user1@example.com")

	client, err := s.upstream.Dial(s.newClientConfig("username", "route1", user.Email))
	s.Require().NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	s.Require().NoError(err)

	_, err = dbClient.Put(s.env.Context(), &databroker.PutRequest{
		Records: []*databroker.Record{
			{
				Type:       "type.googleapis.com/session.SessionBinding",
				Id:         "sshkey-" + gossh.FingerprintSHA256(user.SSHKey.PublicKey()),
				ModifiedAt: timestamppb.Now(),
				DeletedAt:  timestamppb.Now(),
			},
		},
	})
	s.Require().NoError(err)
	sess.Wait()
	err = client.Wait()
	s.ErrorContains(err, "ssh: disconnect, reason 2")
	s.ErrorContains(err, "Permission Denied: no longer authorized{via_upstream}")
}

func (s *SSHTestSuite) TestDirectTcpipSession() {
	user1 := s.lookupUser("user1@example.com")

	s.start(
		[]RouteOptions{
			{
				Name: "route1",
				PPLTemplate: `
allow:
  and:
    - email:
        is: "user1@example.com"
`,
			},
			{
				Name: "route2",
				PPLTemplate: `
allow:
  and:
    - email:
        is: "user1@example.com"
    - ssh_username:
        is: notdemo
`,
			},
		},
		// Tell the upstream to only allow access to this user's public key instead
		// of trusting pomerium's user ca key
		WithSSHUpstreamOptions(upstreams.WithAuthorizedKey(user1.SSHKey.PublicKey(), "demo")),
	)

	s.Run("invalid non-direct connection", func() {
		_, err := s.upstream.Dial(s.newClientConfig("demo", "route1", user1.Email))
		s.ErrorContains(err, "Permission Denied")
	})

	s.Run("invalid user in dest addr", func() {
		client, err := s.upstream.Dial(s.newClientConfig("demo", "", user1.Email))
		s.Require().NoError(err)
		defer client.Close()

		_, _, err = client.OpenChannel("direct-tcpip", gossh.Marshal(ssh.ChannelOpenDirectMsg{
			DestAddr: "demo@route1",
			SrcAddr:  "127.0.0.1",
		}))
		s.ErrorContains(err, "access denied{via_upstream}")
	})
	s.Run("ok", func() {
		client, err := s.upstream.Dial(s.newClientConfig("demo", "", user1.Email))
		s.Require().NoError(err)
		defer client.Close()

		channel, requestsC, err := client.OpenChannel("direct-tcpip", gossh.Marshal(ssh.ChannelOpenDirectMsg{
			DestAddr: "route1",
			SrcAddr:  "127.0.0.1",
		}))
		s.Require().NoError(err)
		go gossh.DiscardRequests(requestsC)
		defer channel.Close()

		clientConn, newChannel, requests, err := gossh.NewClientConn(upstreams.NewRWConn(channel, channel), "", &gossh.ClientConfig{
			User: "demo",
			Auth: []gossh.AuthMethod{
				gossh.PublicKeys(user1.SSHKey),
			},
			HostKeyCallback: gossh.FixedHostKey(newPublicKey(s.T(), s.UpstreamHostKey.Public())),
		})
		s.Require().NoError(err)
		directClient := gossh.NewClient(clientConn, newChannel, requests)

		VerifyWorkingShell(s.T(), directClient)
	})

	s.Run("unauthorized by ppl username", func() {
		client, err := s.upstream.Dial(s.newClientConfig("demo", "", user1.Email))
		s.Require().NoError(err)
		defer client.Close()

		direct := ssh.ChannelOpenDirectMsg{
			DestAddr: "route2",
			SrcAddr:  "127.0.0.1",
		}
		_, _, err = client.OpenChannel("direct-tcpip", gossh.Marshal(direct))
		// note: this error comes from the go ssh client
		s.ErrorContains(err, "Permission Denied")
	})

	s.Run("authorized by ppl username, but wrong user", func() {
		client, err := s.upstream.Dial(s.newClientConfig("notdemo", "", user1.Email))
		s.Require().NoError(err)
		defer client.Close()

		channel, requestsC, err := client.OpenChannel("direct-tcpip", gossh.Marshal(ssh.ChannelOpenDirectMsg{
			DestAddr: "route2",
			SrcAddr:  "127.0.0.1",
		}))
		s.Require().NoError(err)
		go gossh.DiscardRequests(requestsC)
		defer channel.Close()

		_, _, _, err = gossh.NewClientConn(upstreams.NewRWConn(channel, channel), "", &gossh.ClientConfig{
			User: "notdemo",
			Auth: []gossh.AuthMethod{
				gossh.PublicKeys(user1.SSHKey),
			},
			HostKeyCallback: gossh.FixedHostKey(newPublicKey(s.T(), s.UpstreamHostKey.Public())),
		})
	})

	s.Run("direct-tcpip username swap", func() {
		// There is nothing stopping a client from passing the ppl username criteria
		// check on the initial connection, then swapping to a different username
		// for the nested connection. Pomerium cannot read the nested connection so
		// there's no way to apply policy rules there. However, in this mode the
		// downstream client must authorize directly with the real upstream anyway,
		// so if they can log in then they really are authorized no matter what.
		//
		// For this reason, it is not particularly useful to use the ssh_username
		// criteria for routes intended to be used in jump-host mode.

		client, err := s.upstream.Dial(s.newClientConfig("demo", "", user1.Email))
		s.Require().NoError(err)
		defer client.Close()

		channel, requestsC, err := client.OpenChannel("direct-tcpip", gossh.Marshal(ssh.ChannelOpenDirectMsg{
			DestAddr: "route1",
			SrcAddr:  "127.0.0.1",
		}))
		s.Require().NoError(err)
		go gossh.DiscardRequests(requestsC)
		defer channel.Close()

		_, _, _, err = gossh.NewClientConn(upstreams.NewRWConn(channel, channel), "", &gossh.ClientConfig{
			User: "demo",
			Auth: []gossh.AuthMethod{
				gossh.PublicKeys(user1.SSHKey),
			},
			HostKeyCallback: gossh.FixedHostKey(newPublicKey(s.T(), s.UpstreamHostKey.Public())),
		})
	})

	s.Run("multiple sessions", func() {
		client, err := s.upstream.Dial(s.newClientConfig("notdemo", "", user1.Email))
		s.Require().NoError(err)
		defer client.Close()

		channel1, requestsC1, err := client.OpenChannel("direct-tcpip", gossh.Marshal(ssh.ChannelOpenDirectMsg{
			DestAddr: "route2",
			SrcAddr:  "127.0.0.1",
		}))
		s.Require().NoError(err)
		go gossh.DiscardRequests(requestsC1)
		defer channel1.Close()

		clientConn1, newChannel1, requests1, err := gossh.NewClientConn(upstreams.NewRWConn(channel1, channel1), "", &gossh.ClientConfig{
			User: "demo",
			Auth: []gossh.AuthMethod{
				gossh.PublicKeys(user1.SSHKey),
			},
			HostKeyCallback: gossh.FixedHostKey(newPublicKey(s.T(), s.UpstreamHostKey.Public())),
		})
		s.Require().NoError(err)
		directClient1 := gossh.NewClient(clientConn1, newChannel1, requests1)

		VerifyWorkingShell(s.T(), directClient1)

		// Attempting to open a second channel after the handoff will error. The
		// only allowed messages are ChannelData (containing the encapsulated
		// connection traffic) and ChannelClose/EOF
		_, _, err = client.OpenChannel("direct-tcpip", gossh.Marshal(ssh.ChannelOpenDirectMsg{
			DestAddr: "route2",
			SrcAddr:  "127.0.0.1",
		}))
		s.Require().Error(err)

		// The above channel open attempt will kill the entire connection.
		stop := time.AfterFunc(5*time.Second, func() {
			s.Fail("timed out waiting for connection to close")
			client.Close()
		})
		err = client.Wait()
		stop.Stop()
		s.Require().ErrorContains(err, "EOF")
	})
}

func (s *SSHTestSuite) TestDirectTcpipDisabled() {
	user1 := s.lookupUser("user1@example.com")

	s.start(
		[]RouteOptions{
			{
				Name: "route1",
				PPLTemplate: `
allow:
  and:
    - email:
        is: "user1@example.com"
`,
			},
		},
		WithSSHUpstreamOptions(upstreams.WithAuthorizedKey(user1.SSHKey.PublicKey(), "demo")),
		WithEnableDirectTcpip(false),
	)

	client, err := s.upstream.Dial(s.newClientConfig("demo", "", user1.Email))
	s.Require().NoError(err)
	defer client.Close()

	direct := ssh.ChannelOpenDirectMsg{
		DestAddr: "route1",
		SrcAddr:  "127.0.0.1",
	}
	_, _, err = client.OpenChannel("direct-tcpip", gossh.Marshal(direct))
	s.ErrorContains(err, "direct-tcpip channels are not enabled")
}

func (s *SSHTestSuite) TestLoginLogout() {
	s.start([]RouteOptions{
		{
			Name: "route1",
			PPLTemplate: `
allow:
  and:
    - email:
        is: "user1@example.com"
`,
		},
	})

	client, err := s.upstream.Dial(s.newClientConfig("username", "", "user1@example.com"))
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
	s.start([]RouteOptions{
		{
			Name: "route1",
			PPLTemplate: `
allow:
  and:
    - email:
        is: "user1@example.com"
`,
		},
	})

	client, err := s.upstream.Dial(s.newClientConfig("username", "", "user1@example.com"))
	s.Require().NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	s.Require().NoError(err)
	defer sess.Close()

	output, err := sess.CombinedOutput("whoami")
	s.Require().NoError(err)
	s.Regexp((`
User ID:    .*
Session ID: .+
Expires at: .* \(in \d+h\d+m\d+s\)
Claims:
  aud: "CLIENT_ID"
  email: "user1@example.com"
  exp: .* \(in \d+h\d+m\d+s\)
  family_name: ""
  given_name: ""
  iat: .* \(\d+s ago\)
  iss: "https://mock-idp\..*"
  name: ""
  sub: ".*"
`[1:]), string(output))
}

func (s *SSHTestSuite) TestRateLimitService(t *testing.T) {
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

	s.env.AddOption(pomerium.WithAuthorizeServerOptions(
		authorize.WithRateLimitServer(rls),
	))

	s.start([]RouteOptions{
		{
			Name: "route1",
			PPLTemplate: `
allow:
  and:
    - email:
        is: "user1@example.com"
`,
		},
	})

	cc := s.newClientConfig("username", "route1", "user1@example.com")
	client1, err := s.upstream.Dial(cc)
	require.NoError(t, err)
	defer client1.Close()

	VerifyWorkingShell(t, client1)

	_, err = s.upstream.Dial(cc)
	require.Error(t, err)
	require.ErrorContains(t, err, "handshake failed")
}

func TestSSH(t *testing.T) {
	idpUsers := []IdpUserOptions{}
	for i := range 50 {
		idpUsers = append(idpUsers,
			IdpUserOptions{
				User: mockidp.User{
					Email: fmt.Sprintf("user%d@example.com", i+1),
				},
				PublicKeyType: Regular,
			},
			IdpUserOptions{
				User: mockidp.User{
					Email: fmt.Sprintf("certuser%d@example.com", i+1),
				},
				PublicKeyType: CertKey,
			},
		)
	}

	suite.Run(t, &SSHTestSuite{
		Opts: SSHTestSuiteOptions{
			IdpUsers: idpUsers,
		},
	})
}

type echoShell struct {
	t *testing.T
}

func (sh echoShell) handleConnection(_ *gossh.ServerConn, chans <-chan gossh.NewChannel, reqs <-chan *gossh.Request) {
	var wg sync.WaitGroup
	defer wg.Wait()

	// Reject any global requests from the client.
	wg.Go(func() {
		gossh.DiscardRequests(reqs)
	})

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
