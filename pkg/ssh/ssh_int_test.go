package ssh_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
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

const (
	idpUserMaxRoutes = 50
	idpUserMaxUsers  = 7
)

type RouteOptions struct {
	Name        string // without ssh:// prefix
	PPLTemplate string
	PPL         string               // skips templating; mutually exclusive with PPLTemplate
	EditPolicy  func(*config.Policy) // after setting PPL
}

type IdpUser struct {
	IdpUserOptions

	SSHKey gossh.Signer
}

type SSHTestSuiteOptions struct {
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

func (s *SSHTestSuite) toCertKey(pk gossh.Signer) gossh.Signer {
	caSigner, err := gossh.NewSignerFromKey(s.ClientCAKey)
	s.Require().NoError(err)
	cert := &gossh.Certificate{
		CertType:    gossh.UserCert,
		Key:         pk.PublicKey(),
		ValidAfter:  uint64(time.Now().Add(-1 * time.Minute).Unix()),
		ValidBefore: uint64(time.Now().Add(1 * time.Hour).Unix()),
	}
	cert.SignCert(rand.Reader, caSigner)

	certKey, err := gossh.NewCertSigner(cert, pk)
	s.Require().NoError(err)
	return certKey
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
		return &IdpUser{
			IdpUserOptions: opts,
			SSHKey:         s.toCertKey(sshKey),
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

type TemplateContext struct {
	ClientCAKey string
}

func (s *SSHTestSuite) getTemplateContext() TemplateContext {
	return TemplateContext{
		ClientCAKey: strings.TrimSpace(string(gossh.MarshalAuthorizedKey(newPublicKey(s.T(), s.ClientCAKey.Public())))),
	}
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

type routeTestCase struct {
	testName string
	opts     RouteOptions
	testFunc func(RouteTestAPI)
	api      *routeTestAPI
}

type RouteTests struct {
	s            *SSHTestSuite
	subtestCount int
	testCases    []routeTestCase
	modes        []PublicKeyType
}

func (s *SSHTestSuite) InitRouteTests(modes []PublicKeyType) *RouteTests {
	s.Require().NotEmpty(modes)
	return &RouteTests{
		s:     s,
		modes: modes,
	}
}

type RouteTestAPI interface {
	RouteName() string
	RouteUserName(userPlaceholder int) string
	RouteUserEmail(userPlaceholder int) string
	StaticUserName(userPlaceholder int) string  // 0='A', 1='B', etc.
	StaticUserEmail(userPlaceholder int) string // 0='A', 1='B', etc.
}

type routeTestAPI struct {
	routeName     string
	routeUserFmt  string
	staticUserFmt string
}

func (api *routeTestAPI) RouteName() string {
	return api.routeName
}

func (api *routeTestAPI) RouteUserName(userPlaceholder int) string {
	return fmt.Sprintf(api.routeUserFmt, userPlaceholder)
}

func (api *routeTestAPI) RouteUserEmail(userPlaceholder int) string {
	return fmt.Sprintf(api.routeUserFmt, userPlaceholder) + "@example.com"
}

func (api *routeTestAPI) StaticUserName(userPlaceholder int) string {
	return fmt.Sprintf(api.staticUserFmt, userPlaceholder)
}

func (api *routeTestAPI) StaticUserEmail(userPlaceholder int) string {
	return fmt.Sprintf(api.staticUserFmt, userPlaceholder) + "@example.com"
}

func (rt *RouteTests) AddRouteTest(pplTemplate string, fn func(api RouteTestAPI)) {
	rt.s.Require().NotContains(pplTemplate, "\t", "ppl template yaml must not contain tab characters")
	rt.subtestCount++
	tcNamePrefix := fmt.Sprintf("route-test-%d", rt.subtestCount)

	for _, mode := range rt.modes {
		rt.s.Require().Less(len(rt.testCases), idpUserMaxRoutes, "too many route tests; increase the value of idpUserMaxRoutes")
		var routeUserFmt string
		var staticUserFmt string
		var tcNameSuffix string
		routeName := fmt.Sprintf("route%d", len(rt.testCases))
		switch mode {
		case Regular:
			routeUserFmt = routeName + "-user%d"
			staticUserFmt = "user%c"
			tcNameSuffix = ""
		case CertKey:
			routeUserFmt = routeName + "-certuser%d"
			staticUserFmt = "certuser%c"
			tcNameSuffix = "-certkeys"
		default:
			panic("unimplemented mode")
		}
		template := template.New("route-tests").
			Funcs(template.FuncMap{
				"routeUserPublicKey": func(userNum int) string {
					targetEmail := fmt.Sprintf(routeUserFmt, userNum) + "@example.com"
					for _, user := range rt.s.idpUsers {
						if user.Email == targetEmail {
							return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(user.SSHKey.PublicKey())))
						}
					}
					return "<error>"
				},
				"routeUserName": func(userPlaceholder int) string {
					rt.s.Require().Less(userPlaceholder, idpUserMaxUsers)
					return fmt.Sprintf(routeUserFmt, userPlaceholder)
				},
				"staticUserName": func(userPlaceholder uint) string {
					rt.s.Require().Less(userPlaceholder, idpUserMaxUsers)
					return fmt.Sprintf(staticUserFmt, 'A'+userPlaceholder)
				},
				"routeUserEmail": func(userPlaceholder int) string {
					rt.s.Require().Less(userPlaceholder, idpUserMaxUsers)
					return fmt.Sprintf(routeUserFmt, userPlaceholder) + "@example.com"
				},
				"staticUserEmail": func(userPlaceholder uint) string {
					rt.s.Require().Less(userPlaceholder, idpUserMaxUsers)
					return fmt.Sprintf(staticUserFmt, 'A'+userPlaceholder) + "@example.com"
				},
			})
		var out bytes.Buffer
		tmpl, err := template.Parse(pplTemplate)
		rt.s.Require().NoError(err, "invalid template input")
		err = tmpl.Execute(&out, rt.s.getTemplateContext())
		rt.s.Require().NoError(err, "failed to execute template")
		rt.testCases = append(rt.testCases, routeTestCase{
			testName: tcNamePrefix + tcNameSuffix,
			opts: RouteOptions{
				Name: routeName,
				PPL:  out.String(),
			},
			testFunc: fn,
			api: &routeTestAPI{
				routeName:     routeName,
				routeUserFmt:  routeUserFmt,
				staticUserFmt: staticUserFmt,
			},
		})
	}
}

func (rt *RouteTests) Start(startOpts ...startOption) {
	rt.s.T().Helper()
	routes := []RouteOptions{}
	for _, tc := range rt.testCases {
		routes = append(routes, tc.opts)
	}
	rt.s.start(routes, startOpts...)
	for _, tc := range rt.testCases {
		rt.s.Run(tc.testName, func() {
			rt.s.T().Helper()
			tc.testFunc(tc.api)
		})
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
			From(values.Const("ssh://" + route.Name))
		if route.PPL != "" {
			r.PPL(route.PPL)
		} else if route.PPLTemplate != "" {
			var out bytes.Buffer
			tmpl, err := s.template.Parse(route.PPLTemplate)
			s.Require().NoError(err, "invalid template input")
			err = tmpl.Execute(&out, s.getTemplateContext())
			s.Require().NoError(err, "failed to execute template")
			r.PPL(out.String())
		}
		if route.EditPolicy != nil {
			r.Policy(route.EditPolicy)
		}
	}
	s.env.AddUpstream(s.upstream)
	s.clientConfigUsersSeen = map[string]struct{}{}

	s.env.Start()
	snippets.WaitStartupComplete(s.env)
	if s.T().Failed() {
		s.FailNow("test environment failed to start")
	}
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
	if matched, _ := regexp.MatchString(`user[A-Z]@example.com`, userEmail); !matched {
		s.Require().NotContains(s.clientConfigUsersSeen, userEmail,
			"test bug: do not call newClientConfig with the same route-scoped user twice during the same test")
		s.clientConfigUsersSeen[userEmail] = struct{}{}
	}
	user := s.lookupUser(userEmail)
	username := loginName
	if route != "" {
		username += "@" + route
	}
	return &gossh.ClientConfig{
		User: username,
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(user.SSHKey),
			gossh.KeyboardInteractive(func(_, instruction string, _ []string, _ []bool) (answers []string, err error) {
				return s.challengeImpl.Do(s.env.Context(), instruction, user.Email)
			}),
		},
		HostKeyCallback: gossh.FixedHostKey(newPublicKey(s.T(), s.ServerHostKey.Public())),
	}
}

func (s *SSHTestSuite) dialFrom127002(cc *gossh.ClientConfig) (*gossh.Client, error) {
	s.T().Helper()
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.2"),
			Port: 0,
		},
	}
	addr := s.env.Config().Options.SSHAddr
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := gossh.NewClientConn(conn, addr, cc)
	if err != nil {
		return nil, err
	}
	return gossh.NewClient(c, chans, reqs), nil
}

func expectAuthSequence(t *testing.T, cc *gossh.ClientConfig, attemptListeners []func(ctx *gossh.ClientAuthContext) gossh.AuthMethod) (verify func()) {
	require.Nil(t, cc.AuthCallback, "test bug: do not reuse gossh.ClientConfig instances")
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

func seqPublicKeyAcceptedThenKbdInt(t *testing.T) []func(*gossh.ClientAuthContext) gossh.AuthMethod {
	return []func(ctx *gossh.ClientAuthContext) gossh.AuthMethod{
		func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
			t.Helper()
			require.Equal(t, []string{"publickey"}, ctx.AllowedMethods)
			require.Empty(t, ctx.PartialSuccessMethods)
			require.Equal(t, []string{"none"}, ctx.TriedMethods)
			return nil
		},
		func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
			t.Helper()
			require.Equal(t, []string{"keyboard-interactive"}, ctx.AllowedMethods)
			require.Equal(t, []string{"publickey"}, ctx.PartialSuccessMethods)
			require.Equal(t, []string{"none"}, ctx.TriedMethods)
			return nil
		},
	}
}

func seqPublicKeyRejected(t *testing.T) []func(*gossh.ClientAuthContext) gossh.AuthMethod {
	return []func(ctx *gossh.ClientAuthContext) gossh.AuthMethod{
		func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
			t.Helper()
			require.Equal(t, []string{"publickey"}, ctx.AllowedMethods)
			require.Empty(t, ctx.PartialSuccessMethods)
			require.Equal(t, []string{"none"}, ctx.TriedMethods)
			return nil
		},
		func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
			t.Helper()
			// second publickey attempt will fail (assuming only one configured key)
			require.Equal(t, []string{"publickey"}, ctx.AllowedMethods)
			require.Empty(t, ctx.PartialSuccessMethods)
			require.Equal(t, []string{"none", "publickey"}, ctx.TriedMethods)
			return nil
		},
	}
}

func seqDeniedImmediately(t *testing.T) []func(*gossh.ClientAuthContext) gossh.AuthMethod {
	return []func(ctx *gossh.ClientAuthContext) gossh.AuthMethod{
		func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
			t.Helper()
			require.Equal(t, []string{"publickey"}, ctx.AllowedMethods)
			require.Empty(t, ctx.PartialSuccessMethods)
			require.Equal(t, []string{"none"}, ctx.TriedMethods)
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
func seqPublicKeyAcceptedAfter1RetryThenKbdInit(t *testing.T, keys [2]gossh.Signer, kbdInt gossh.AuthMethod) []func(*gossh.ClientAuthContext) gossh.AuthMethod {
	return []func(ctx *gossh.ClientAuthContext) gossh.AuthMethod{
		func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
			t.Helper()
			require.Equal(t, []string{"publickey"}, ctx.AllowedMethods)
			require.Empty(t, ctx.PartialSuccessMethods)
			require.Equal(t, []string{"none"}, ctx.TriedMethods)
			return gossh.PublicKeys(keys[0])
		},
		func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
			t.Helper()
			require.Equal(t, []string{"publickey"}, ctx.AllowedMethods)
			require.Empty(t, ctx.PartialSuccessMethods)
			require.Equal(t, []string{"none", "publickey"}, ctx.TriedMethods)
			return gossh.PublicKeys(keys[1])
		},
		func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
			t.Helper()
			require.Equal(t, []string{"keyboard-interactive"}, ctx.AllowedMethods)
			require.Equal(t, []string{"publickey"}, ctx.PartialSuccessMethods)
			require.Equal(t, []string{"none", "publickey"}, ctx.TriedMethods)
			return kbdInt
		},
	}
}

const sshErrMsgPublicKeyAuthFailed = "ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain"

func (s *SSHTestSuite) TestNormalSession() {
	rt := s.InitRouteTests([]PublicKeyType{Regular, CertKey})

	// Different users are used for each subtest case, otherwise earlier tests
	// can affect later tests due to sessions/session bindings persisting.
	//
	// Users are referenced in PPL templates and within the test body using
	// placeholder numbers which are expanded to email addresses, public keys,
	// etc. corresponding to those users. The users are created ahead of time
	// with a predictable naming scheme.
	//
	// Placeholders with the same number expand to different users in each
	// route test (calls to AddRouteTest), for example `{{ routeUserEmail 1 }}`
	// will expand to "route1-user1@example.com" for the first test, then
	// "route2-user1@example.com" for the second test, and so on. The placeholder
	// numbers in the ppl template functions and the RouteTestAPI functions are
	// used the same way and refer to the same users.
	//
	// Calls to `s.Run()` within a route test are only for logical grouping of
	// test cases and use the same placeholder scope. This means if you call
	// api.RouteUserEmail(1) in separate s.Run() subtests within a single route
	// test, it will expand to the same user. Be careful of copy-paste errors.
	//
	// Some utility functions like newClientConfig will keep track of
	// users and fail if the same user is passed in twice for any given top-level
	// test.
	//
	// The tests defined by AddRouteTest may generate multiple copies of the
	// subtests with different users, for each public key type passed to
	// InitRouteTests.

	rt.AddRouteTest(`
allow:
  and:
    - email:
        in:
          - "{{ routeUserEmail 1 }}"
`, func(api RouteTestAPI) {
		s.Run("authorized via email", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(1))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
		s.Run("email unauthorized", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(2))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
	})

	rt.AddRouteTest(`
allow:
  and:
    - ssh_publickey:
        - "{{ routeUserPublicKey 1 }}"
    - email:
        in:
          - "{{ routeUserEmail 1 }}"
`, func(api RouteTestAPI) {
		s.Run("authorized via email and public key", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(1))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
		s.Run("public key unauthorized", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(2))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyRejected(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, sshErrMsgPublicKeyAuthFailed)
		})
	})

	rt.AddRouteTest(`
allow:
  and:
    - ssh_publickey:
      - "{{ routeUserPublicKey 1 }}"
      - "{{ routeUserPublicKey 2 }}"
      - "{{ routeUserPublicKey 3 }}"
      - "{{ routeUserPublicKey 4 }}"
    - email:
        in:
          - "{{ routeUserEmail 1 }}"
          - "{{ routeUserEmail 3 }}"
`, func(api RouteTestAPI) {
		s.Run("authorized via email and public key", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(1))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
		s.Run("public key matches criteria but email is unauthorized", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(2))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
		s.Run("public key accepted after retry", func() {
			randomKey := newSignerFromKey(s.T(), newSSHKey(s.T()))
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(3))
			cc.Auth = nil
			verify := expectAuthSequence(s.T(), cc,
				seqPublicKeyAcceptedAfter1RetryThenKbdInit(s.T(),
					[2]gossh.Signer{randomKey, s.lookupUser(api.RouteUserEmail(3)).SSHKey},
					gossh.KeyboardInteractive(func(_, instruction string, _ []string, _ []bool) (answers []string, err error) {
						return s.challengeImpl.Do(s.env.Context(), instruction, api.RouteUserEmail(3))
					})))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
		s.Run("public key accepted after retry but email is unauthorized", func() {
			randomKey := newSignerFromKey(s.T(), newSSHKey(s.T()))
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(4))
			cc.Auth = nil
			verify := expectAuthSequence(s.T(), cc,
				seqPublicKeyAcceptedAfter1RetryThenKbdInit(s.T(),
					[2]gossh.Signer{randomKey, s.lookupUser(api.RouteUserEmail(4)).SSHKey},
					gossh.KeyboardInteractive(func(_, instruction string, _ []string, _ []bool) (answers []string, err error) {
						return s.challengeImpl.Do(s.env.Context(), instruction, api.RouteUserEmail(4))
					})))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
	})

	rt.AddRouteTest(`
allow:
  and:
    - authenticated_user: {}
deny:
  or:
    - source_ip: "127.0.0.1"
`, func(api RouteTestAPI) {
		s.Run("source ip unauthorized", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(1))
			verify := expectAuthSequence(s.T(), cc, seqDeniedImmediately(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
		s.Run("source ip not unauthorized", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(2))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()

			client, err := s.dialFrom127002(cc)
			s.Require().NoError(err)

			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
	})

	rt.AddRouteTest(`
allow:
  and:
    - authenticated_user: {}
deny:
  or:
    - ssh_username: "root"
    - ssh_publickey: "{{ routeUserPublicKey 3 }}"
`, func(api RouteTestAPI) {
		s.Run("ssh username denied", func() {
			cc := s.newClientConfig("root", api.RouteName(), api.RouteUserEmail(1))
			verify := expectAuthSequence(s.T(), cc, seqDeniedImmediately(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
		s.Run("ssh username not denied", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(2))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
		s.Run("ssh public key denied", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(3))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyRejected(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, sshErrMsgPublicKeyAuthFailed)
		})
		s.Run("ssh public key not denied", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(4))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
	})

	rt.AddRouteTest(`
allow:
  and:
    - source_ip: "127.0.0.2"
    - ssh_username: "username"
    - authenticated_user: {}
`, func(api RouteTestAPI) {
		s.Run("source ip not allowed", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(1))
			verify := expectAuthSequence(s.T(), cc, seqDeniedImmediately(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
		s.Run("source ip allowed, but username not allowed", func() {
			cc := s.newClientConfig("root", api.RouteName(), api.RouteUserEmail(2))
			verify := expectAuthSequence(s.T(), cc, seqDeniedImmediately(s.T()))
			defer verify()
			_, err := s.dialFrom127002(cc)
			s.ErrorContains(err, "Permission Denied")
		})
		s.Run("source ip and username allowed", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(3))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()

			client, err := s.dialFrom127002(cc)
			s.Require().NoError(err)

			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
		s.Run("neither source ip nor username allowed", func() {
			cc := s.newClientConfig("root", api.RouteName(), api.RouteUserEmail(4))
			verify := expectAuthSequence(s.T(), cc, seqDeniedImmediately(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
	})

	rt.AddRouteTest(`
allow:
  and:
    - ssh_publickey: "{{ routeUserPublicKey 2 }}"
    - authenticated_user: {}
deny:
  or:
    - ssh_publickey: "{{ routeUserPublicKey 3 }}"
`, func(api RouteTestAPI) {
		s.Run("public key not allowed", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(1))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyRejected(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, sshErrMsgPublicKeyAuthFailed)
		})
		s.Run("public key allowed and not denied", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(2))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
		s.Run("public key denied", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(3))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyRejected(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, sshErrMsgPublicKeyAuthFailed)
		})
	})

	rt.AddRouteTest(`
allow:
  and:
    - ssh_publickey: "{{ routeUserPublicKey 2 }}"
    - authenticated_user: {}
`, func(api RouteTestAPI) {
		s.Run("public key not allowed", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(1))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyRejected(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, sshErrMsgPublicKeyAuthFailed)
		})
		s.Run("public key allowed", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(2))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
	})

	rt.AddRouteTest(`
allow:
  and:
    - ssh_publickey:
        - "{{ routeUserPublicKey 2 }}"
`, func(api RouteTestAPI) {
		// note: this policy is invalid, but that only becomes apparent after
		// successfully authenticating with a public key
		s.Run("public key unauthorized", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(1))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyRejected(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, sshErrMsgPublicKeyAuthFailed)
		})
		s.Run("public key accepted, but unauthorized due to missing session criteria", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(2))
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

	rt.AddRouteTest(`
allow:
  and:
    - accept: {}
`, func(api RouteTestAPI) {
		s.Run("unauthorized due to invalid route", func() {
			cc := s.newClientConfig("username", api.RouteName(), api.RouteUserEmail(1))
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

	rt.AddRouteTest(`
allow:
  and:
    - ssh_ca: "{{ .ClientCAKey }}"
    - email: "{{ routeUserEmail 1 }}"
`, func(api RouteTestAPI) {
		s.Run("authorized cert key", func() {
			user := s.lookupUser(api.RouteUserEmail(1))
			randomUserKey := newSignerFromKey(s.T(), newSSHKey(s.T()))
			certKey := s.toCertKey(randomUserKey)
			cc := s.newClientConfig("username", api.RouteName(), user.Email)
			cc.Auth = []gossh.AuthMethod{
				gossh.PublicKeys(certKey),
				gossh.KeyboardInteractive(func(_, instruction string, _ []string, _ []bool) (answers []string, err error) {
					return s.challengeImpl.Do(s.env.Context(), instruction, user.Email)
				}),
			}
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})

		s.Run("cert key signed by wrong ca", func() {
			user := s.lookupUser(api.RouteUserEmail(2))
			randomUserKey := newSignerFromKey(s.T(), newSSHKey(s.T()))
			wrongCaSigner := newSignerFromKey(s.T(), newSSHKey(s.T()))
			cert := &gossh.Certificate{
				CertType:    gossh.UserCert,
				Key:         randomUserKey.PublicKey(),
				ValidAfter:  uint64(time.Now().Add(-1 * time.Minute).Unix()),
				ValidBefore: uint64(time.Now().Add(1 * time.Hour).Unix()),
			}
			cert.SignCert(rand.Reader, wrongCaSigner)

			certKey, err := gossh.NewCertSigner(cert, randomUserKey)
			s.Require().NoError(err)

			cc := s.newClientConfig("username", api.RouteName(), user.Email)
			cc.Auth = []gossh.AuthMethod{
				gossh.PublicKeys(certKey),
				gossh.KeyboardInteractive(func(_, instruction string, _ []string, _ []bool) (answers []string, err error) {
					return s.challengeImpl.Do(s.env.Context(), instruction, user.Email)
				}),
			}
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyRejected(s.T()))
			defer verify()
			_, err = s.upstream.Dial(cc)
			s.ErrorContains(err, sshErrMsgPublicKeyAuthFailed)
		})
	})

	rt.AddRouteTest(`
allow:
  and:
    - ssh_username_matches_email: {}
    - domain: "example.com"
`, func(api RouteTestAPI) {
		s.Run("username matching email", func() {
			cc := s.newClientConfig(api.RouteUserName(1), api.RouteName(), api.RouteUserEmail(1))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
		s.Run("username not matching email", func() {
			// In this case the public key will be accepted initially, because a
			// session is required to match the username against an email. Once the
			// session is obtained, then the request will be denied
			cc := s.newClientConfig("wrongusername", api.RouteName(), api.RouteUserEmail(2))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
	})

	rt.AddRouteTest(`
allow:
  and:
    - ssh_username_matches_claim: "user"
    - email: "{{ routeUserEmail 1 }}"
`, func(api RouteTestAPI) {
		s.Run("username matching claim", func() {
			// the "user" claim is set up to be "route#-user#"
			cc := s.newClientConfig(api.RouteUserName(1), api.RouteName(), api.RouteUserEmail(1))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			client, err := s.upstream.Dial(cc)
			s.Require().NoError(err)
			VerifyWorkingShell(s.T(), client)
			client.Close()
		})
		s.Run("username not matching claim", func() {
			cc := s.newClientConfig("wrongusername", api.RouteName(), api.RouteUserEmail(2))
			verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
			defer verify()
			_, err := s.upstream.Dial(cc)
			s.ErrorContains(err, "Permission Denied")
		})
	})

	rt.Start()

	s.Run("internal cli", func() {
		cc := s.newClientConfig("username", "", "userA@example.com")
		verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
		defer verify()
		client, err := s.upstream.Dial(cc)
		s.Require().NoError(err)
		client.Close()
	})
}

func (s *SSHTestSuite) TestReuseAuthorizedSession() {
	s.start([]RouteOptions{
		{
			Name: "route1",
			PPLTemplate: `
allow:
  and:
    - email:
        is: "userA@example.com"
`,
		},
		{
			Name: "route2",
			PPLTemplate: `
allow:
  and:
    - ssh_publickey:
        - "{{ userPublicKey "userA@example.com" }}"
    - email:
        is: "userA@example.com"
`,
		},
		{
			Name: "route3",
			PPLTemplate: `
allow:
  and:
    - ssh_publickey:
        - "{{ userPublicKey "userB@example.com" }}"
    - email:
        is: "userB@example.com"
`,
		},
		{
			Name: "route4",
			PPLTemplate: `
allow:
  and:
    - email:
        is: "userB@example.com"
`,
		},
	})

	publicKeyMethodOnly := []func(ctx *gossh.ClientAuthContext) gossh.AuthMethod{
		func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
			s.T().Helper()
			s.Require().Equal([]string{"publickey"}, ctx.AllowedMethods)
			s.Require().Empty(ctx.PartialSuccessMethods)
			s.Require().Equal([]string{"none"}, ctx.TriedMethods)
			return nil
		},
	}

	publicKeyMethodFailure := []func(ctx *gossh.ClientAuthContext) gossh.AuthMethod{
		func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
			s.T().Helper()
			s.Require().Equal([]string{"publickey"}, ctx.AllowedMethods)
			s.Require().Empty(ctx.PartialSuccessMethods)
			s.Require().Equal([]string{"none"}, ctx.TriedMethods)
			return nil
		},
		func(ctx *gossh.ClientAuthContext) gossh.AuthMethod {
			s.T().Helper()
			s.Require().Equal([]string{"publickey"}, ctx.AllowedMethods)
			s.Require().Empty(ctx.PartialSuccessMethods)
			s.Require().Equal([]string{"none", "publickey"}, ctx.TriedMethods)
			return nil
		},
	}

	// Log into the internal CLI first to create the session

	{
		cc := s.newClientConfig("username", "", "userA@example.com")
		verify := expectAuthSequence(s.T(), cc, seqPublicKeyAcceptedThenKbdInt(s.T()))
		client, err := s.upstream.Dial(cc)
		s.Require().NoError(err)
		verify()
		s.Require().NoError(client.Close())
	}
	if s.T().Failed() {
		return
	}

	// Log in a few times to a route which this session is authorized for
	for range 5 {
		cc := s.newClientConfig("username", "route1", "userA@example.com")
		verify := expectAuthSequence(s.T(), cc, publicKeyMethodOnly)
		client, err := s.upstream.Dial(cc)
		s.Require().NoError(err)
		verify()
		VerifyWorkingShell(s.T(), client)
		s.Require().NoError(client.Close())
	}

	// Log into a different route with the same session
	{
		cc := s.newClientConfig("username", "route2", "userA@example.com")
		verify := expectAuthSequence(s.T(), cc, publicKeyMethodOnly)
		client, err := s.upstream.Dial(cc)
		s.Require().NoError(err)
		VerifyWorkingShell(s.T(), client)
		s.Require().NoError(client.Close())
		verify()
	}

	// Try to log into other routes which are not authorized for this session
	{
		cc := s.newClientConfig("username", "route3", "userA@example.com")
		verify := expectAuthSequence(s.T(), cc, publicKeyMethodFailure)
		_, err := s.upstream.Dial(cc)
		s.Require().ErrorContains(err, sshErrMsgPublicKeyAuthFailed)
		verify()
	}
	{
		cc := s.newClientConfig("username", "route4", "userA@example.com")
		verify := expectAuthSequence(s.T(), cc, publicKeyMethodOnly)
		_, err := s.upstream.Dial(cc)
		s.Require().ErrorContains(err, "Permission Denied")
		verify()
	}
}

func (s *SSHTestSuite) TestReevaluatePolicyOnConfigChange() {
	s.start([]RouteOptions{
		{
			Name: "route1",
			PPLTemplate: `
allow:
  and:
    - email:
        is: "route1-user1@example.com"
`,
		},
	})

	client, err := s.upstream.Dial(s.newClientConfig("username", "route1", "route1-user1@example.com"))
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

func (s *SSHTestSuite) TestTooManyPublicKeyAttempts() {
	s.start([]RouteOptions{
		{
			Name: "route1",
			PPLTemplate: `
allow:
  and:
    - ssh_publickey:
      - "{{ userPublicKey "route1-user1@example.com" }}"
    - email:
        is: "route1-user1@example.com"
`,
		},
	})

	// Currently the max allowed number of failed public key attempts is 6.
	randomKeys := make([]gossh.Signer, 10)
	for i := range len(randomKeys) {
		randomKeys[i] = newSignerFromKey(s.T(), newSSHKey(s.T()))
	}
	cc := s.newClientConfig("username", "route1", "route1-user1@example.com")
	cc.Auth = []gossh.AuthMethod{
		gossh.PublicKeys(append(randomKeys, s.lookupUser("route1-user1@example.com").SSHKey)...),
		gossh.KeyboardInteractive(func(_, instruction string, _ []string, _ []bool) (answers []string, err error) {
			return s.challengeImpl.Do(s.env.Context(), instruction, "route1-user1@example.com")
		}),
	}

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
	s.ErrorContains(err, "Permission Denied: too many authentication failures")
}

func (s *SSHTestSuite) TestRevokeSession() {
	s.start([]RouteOptions{
		{
			Name: "route1",
			PPLTemplate: `
allow:
  and:
    - email:
        is: "route1-user1@example.com"
`,
		},
	})

	dbClient := s.env.NewDataBrokerServiceClient()
	user := s.lookupUser("route1-user1@example.com")

	client, err := s.upstream.Dial(s.newClientConfig("username", "route1", user.Email))
	s.Require().NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	s.Require().NoError(err)

	revoked := make(chan struct{})
	go func() {
		defer close(revoked)
		sess.Wait()
		err = client.Wait()
		s.ErrorContains(err, "ssh: disconnect, reason 2")
		s.ErrorContains(err, "Permission Denied: no longer authorized{via_upstream}")
	}()

	sessionBindingID := sessionBindingIDFromPublicKey(user.SSHKey.PublicKey())
	_, err = dbClient.Put(s.env.Context(), &databroker.PutRequest{
		Records: []*databroker.Record{
			{
				Type:       "type.googleapis.com/session.SessionBinding",
				Id:         sessionBindingID,
				ModifiedAt: timestamppb.Now(),
				DeletedAt:  timestamppb.Now(),
			},
		},
	})
	s.Require().NoError(err)
	select {
	case <-revoked:
	case <-time.After(10 * time.Second):
		s.Fail("timed out waiting for session to be revoked")
	}
}

func (s *SSHTestSuite) TestDirectTcpipSession() {
	s.start(
		[]RouteOptions{
			{
				Name: "route1",
				PPLTemplate: `
allow:
  and:
    - email:
        in:
          - "route1-user1@example.com"
          - "route1-user2@example.com"
          - "route1-user3@example.com"
          - "route1-user4@example.com"
          - "route1-user5@example.com"
`,
			},
			{
				Name: "route2",
				PPLTemplate: `
allow:
  and:
    - email:
        in:
          - "route2-user1@example.com"
          - "route2-user2@example.com"
          - "route2-user3@example.com"
    - ssh_username:
        is: notdemo
`,
			},
		},
		// Tell the upstream to only allow access to this user's public key instead
		// of trusting pomerium's user ca key
		WithSSHUpstreamOptions(
			upstreams.WithAuthorizedKey(s.lookupUser("route1-user1@example.com").SSHKey.PublicKey(), "demo"),
			upstreams.WithAuthorizedKey(s.lookupUser("route1-user2@example.com").SSHKey.PublicKey(), "demo"),
			upstreams.WithAuthorizedKey(s.lookupUser("route1-user3@example.com").SSHKey.PublicKey(), "demo"),
			upstreams.WithAuthorizedKey(s.lookupUser("route1-user4@example.com").SSHKey.PublicKey(), "demo"),

			upstreams.WithAuthorizedKey(s.lookupUser("route2-user2@example.com").SSHKey.PublicKey(), "demo"),
			upstreams.WithAuthorizedKey(s.lookupUser("route2-user3@example.com").SSHKey.PublicKey(), "demo"),
		),
	)

	s.Run("invalid non-direct connection", func() {
		_, err := s.upstream.Dial(s.newClientConfig("demo", "route1", "route1-user1@example.com"))
		s.ErrorContains(err, "Permission Denied")
	})

	s.Run("invalid user in dest addr", func() {
		client, err := s.upstream.Dial(s.newClientConfig("demo", "", "route1-user2@example.com"))
		s.Require().NoError(err)
		defer client.Close()

		_, _, err = client.OpenChannel("direct-tcpip", gossh.Marshal(ssh.ChannelOpenDirectMsg{
			DestAddr: "demo@route1",
			SrcAddr:  "127.0.0.1",
		}))
		s.ErrorContains(err, "access denied{via_upstream}")
	})
	s.Run("ok", func() {
		client, err := s.upstream.Dial(s.newClientConfig("demo", "", "route1-user3@example.com"))
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
				gossh.PublicKeys(s.lookupUser("route1-user3@example.com").SSHKey),
			},
			HostKeyCallback: gossh.FixedHostKey(newPublicKey(s.T(), s.UpstreamHostKey.Public())),
		})
		s.Require().NoError(err)
		directClient := gossh.NewClient(clientConn, newChannel, requests)

		VerifyWorkingShell(s.T(), directClient)
	})

	s.Run("direct-tcpip ssh_username swap", func() {
		// There is nothing stopping a client from passing the ssh_username criteria
		// check on the initial connection, then swapping to a different username
		// for the nested connection. Pomerium cannot read the nested connection so
		// there's no way to apply policy rules there. However, in this mode the
		// downstream client must authorize directly with the real upstream anyway,
		// so if they can log in then they really are authorized no matter what.
		//
		// For this reason, it is not particularly useful to use the ssh_username
		// criteria for routes intended to be used in jump-host mode.

		client, err := s.upstream.Dial(s.newClientConfig("demo", "", "route1-user4@example.com"))
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
				gossh.PublicKeys(s.lookupUser("route1-user4@example.com").SSHKey),
			},
			HostKeyCallback: gossh.FixedHostKey(newPublicKey(s.T(), s.UpstreamHostKey.Public())),
		})
		s.Require().NoError(err)
		directClient := gossh.NewClient(clientConn, newChannel, requests)

		VerifyWorkingShell(s.T(), directClient)
	})

	s.Run("authorized by pomerium, but public key not allowed by upstream", func() {
		// user5's public key isn't added to the upstream server
		client, err := s.upstream.Dial(s.newClientConfig("demo", "", "route1-user5@example.com"))
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
				gossh.PublicKeys(s.lookupUser("route1-user5@example.com").SSHKey),
			},
			HostKeyCallback: gossh.FixedHostKey(newPublicKey(s.T(), s.UpstreamHostKey.Public())),
		})
		s.ErrorContains(err, sshErrMsgPublicKeyAuthFailed)
	})

	s.Run("unauthorized by ssh_username", func() {
		client, err := s.upstream.Dial(s.newClientConfig("demo", "", "route2-user1@example.com"))
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

	s.Run("authorized by pomerium, but username not allowed by upstream", func() {
		client, err := s.upstream.Dial(s.newClientConfig("notdemo", "", "route2-user2@example.com"))
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
				gossh.PublicKeys(s.lookupUser("route2-user2@example.com").SSHKey),
			},
			HostKeyCallback: gossh.FixedHostKey(newPublicKey(s.T(), s.UpstreamHostKey.Public())),
		})
		s.ErrorContains(err, sshErrMsgPublicKeyAuthFailed)
	})

	s.Run("disallow multiple sessions", func() {
		client, err := s.upstream.Dial(s.newClientConfig("notdemo", "", "route2-user3@example.com"))
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
				gossh.PublicKeys(s.lookupUser("route2-user3@example.com").SSHKey),
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
	user1 := s.lookupUser("route1-user1@example.com")

	s.start(
		[]RouteOptions{
			{
				Name: "route1",
				PPLTemplate: `
allow:
  and:
    - email:
        is: "route1-user1@example.com"
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
        is: "route1-user1@example.com"
`,
		},
	})

	client, err := s.upstream.Dial(s.newClientConfig("username", "", "route1-user1@example.com"))
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
	s.start([]RouteOptions{})

	client, err := s.upstream.Dial(s.newClientConfig("username", "", "userA@example.com"))
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
  email: "userA@example.com"
  exp: .* \(in \d+h\d+m\d+s\)
  family_name: ""
  given_name: ""
  iat: .* \(\d+s ago\)
  iss: "https://mock-idp\..*"
  name: ""
  sub: ".*"
`[1:]), string(output))
}

func (s *SSHTestSuite) TestRateLimitService() {
	ctrl := gomock.NewController(s.T())
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
        is: "route1-user1@example.com"
`,
		},
	})

	cc := s.newClientConfig("username", "route1", "route1-user1@example.com")
	client1, err := s.upstream.Dial(cc)
	s.NoError(err)
	defer client1.Close()

	VerifyWorkingShell(s.T(), client1)

	_, err = s.upstream.Dial(cc)
	s.Require().Error(err)
	s.ErrorContains(err, "handshake failed")
}

func createIdpUsers(publicKeyType PublicKeyType) []IdpUserOptions {
	idpUsers := []IdpUserOptions{}
	// `route[1-30]-user[1-10]@example.com`
	// `route[1-30]-certuser[1-10]@example.com`
	// Use these when testing access to a specific route
	for r := range idpUserMaxRoutes {
		for u := range idpUserMaxUsers {
			idpUsers = append(idpUsers,
				IdpUserOptions{
					User: mockidp.User{
						Email: fmt.Sprintf("route%d-user%d@example.com", r, u),
						Claims: map[string]any{
							"user": fmt.Sprintf("route%d-user%d", r, u),
						},
					},
					PublicKeyType: publicKeyType,
				},
				IdpUserOptions{
					User: mockidp.User{
						Email: fmt.Sprintf("route%d-certuser%d@example.com", r, u),
						Claims: map[string]any{
							"user": fmt.Sprintf("route%d-certuser%d", r, u),
						},
					},
					PublicKeyType: publicKeyType,
				},
			)
		}
	}
	// `user[A-Z]@example.com`
	// `certuser[A-Z]@example.com`
	// Use these when testing access across multiple routes, or to the internal CLI
	for i := 'A'; i <= 'Z'; i++ {
		idpUsers = append(idpUsers,
			IdpUserOptions{
				User: mockidp.User{
					Email: fmt.Sprintf("user%c@example.com", i),
					Claims: map[string]any{
						"user": fmt.Sprintf("user%c", i),
					},
				},
				PublicKeyType: publicKeyType,
			},
			IdpUserOptions{
				User: mockidp.User{
					Email: fmt.Sprintf("certuser%c@example.com", i),
					Claims: map[string]any{
						"user": fmt.Sprintf("certuser%c", i),
					},
				},
				PublicKeyType: publicKeyType,
			},
		)
	}
	return idpUsers
}

func TestSSH(t *testing.T) {
	suite.Run(t, &SSHTestSuite{
		Opts: SSHTestSuiteOptions{
			IdpUsers: createIdpUsers(Regular),
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
