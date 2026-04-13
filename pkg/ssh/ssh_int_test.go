package ssh_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	envoy_service_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/assert"
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
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	sessionpb "github.com/pomerium/pomerium/pkg/grpc/session"
	userpb "github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/ratelimit"
)

//go:generate go tool -modfile ../../internal/tools/go.mod go.uber.org/mock/mockgen -package ssh_test -destination ratelimit_mock_test.go github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3 RateLimitServiceServer

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

func (s *SSHTestSuite) TestDirectTcpipSession_UnauthorizedByPPLUsername() {
	if !strings.Contains(s.PPL, "ssh_username") {
		s.T().Skip()
	}
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

	s.clientConfig.User = "invalid-user"
	client, err := upstream.Dial(s.clientConfig)
	s.Require().NoError(err)
	defer client.Close()

	direct := ssh.ChannelOpenDirectMsg{
		DestAddr: "example",
		SrcAddr:  "127.0.0.1",
	}
	_, _, err = client.OpenChannel("direct-tcpip", gossh.Marshal(direct))
	// note: this error comes from the go ssh client
	s.ErrorContains(err, "Permission Denied")
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
	s.Regexp(strings.TrimSpace(s.executeTemplate(`
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
	`[1:])), string(output))
}

func TestOPKSSHHappyPath(t *testing.T) {
	const (
		userEmail = "fake.user@example.com"
		userSub   = "sub-opkssh-test"
		clientID  = "CLIENT_ID"
	)

	env := testenv.New(t)
	t.Cleanup(env.Stop)

	keys := NewSSHKeys(t)
	idp := scenarios.NewIDP([]*scenarios.User{{Email: userEmail}})
	env.Add(idp)
	env.Add(scenarios.SSH(scenarios.SSHConfig{
		HostKeys:  []any{keys.ServerHostKey},
		UserCAKey: keys.UserCAKey,
	}))
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = map[config.RuntimeFlag]bool{}
		}
		cfg.Options.SSHOPKSSHEnabled = true
		cfg.Options.SSHOPKSSHIssuer = cfg.Options.ProviderURL
		cfg.Options.SSHOPKSSHClientIDs = []string{clientID}
		cfg.Options.RuntimeFlags[config.RuntimeFlagSSHOPKSSH] = true
	}))

	upstream := upstreams.SSH()
	upstream.Route().
		From(values.Const("ssh://example")).
		PPL(`{"allow":{"and":[{"authenticated_user":1}]}}`)
	env.AddUpstream(upstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	_, sshKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cicProtected := buildCICProtected(t, sshKey)
	nonce := computeCICNonce(t, cicProtected)
	idToken := idp.MintIDTokenWithNonce(clientID, userSub, userEmail, nonce)

	compact := buildOPKSSHCompact(t, idToken, cicProtected, sshKey)
	clientSigner := newOPKSSHCertSigner(t, compact, sshKey)
	clientConfig := &gossh.ClientConfig{
		User: "demo",
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(clientSigner),
		},
		HostKeyCallback: gossh.FixedHostKey(newPublicKey(t, keys.ServerHostKey.Public())),
	}

	client, err := upstream.Dial(clientConfig)
	require.NoError(t, err)
	defer client.Close()

	sess, err := client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	output, err := sess.CombinedOutput("whoami")
	require.NoError(t, err)
	assert.Regexp(t,
		`(?s)aud: "CLIENT_ID".*email: "fake\.user@example\.com".*iss: "https://mock-idp\..*".*sub: "sub-opkssh-test"`,
		string(output),
	)
}

func TestOPKSSHHappyPathES256(t *testing.T) {
	const (
		userEmail = "fake.user@example.com"
		userSub   = "sub-opkssh-es256"
		clientID  = "CLIENT_ID"
	)

	env := testenv.New(t)
	t.Cleanup(env.Stop)

	keys := NewSSHKeys(t)
	idp := scenarios.NewIDP([]*scenarios.User{{Email: userEmail}})
	env.Add(idp)
	env.Add(scenarios.SSH(scenarios.SSHConfig{
		HostKeys:  []any{keys.ServerHostKey},
		UserCAKey: keys.UserCAKey,
	}))
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = map[config.RuntimeFlag]bool{}
		}
		cfg.Options.SSHOPKSSHEnabled = true
		cfg.Options.SSHOPKSSHIssuer = cfg.Options.ProviderURL
		cfg.Options.SSHOPKSSHClientIDs = []string{clientID}
		cfg.Options.RuntimeFlags[config.RuntimeFlagSSHOPKSSH] = true
	}))

	upstream := upstreams.SSH()
	upstream.Route().
		From(values.Const("ssh://example")).
		PPL(`{"allow":{"and":[{"authenticated_user":1}]}}`)
	env.AddUpstream(upstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	// Use ECDSA P-256 instead of Ed25519.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cicProtected := buildCICProtected(t, ecKey)
	nonce := computeCICNonce(t, cicProtected)
	idToken := idp.MintIDTokenWithNonce(clientID, userSub, userEmail, nonce)

	compact := buildOPKSSHCompact(t, idToken, cicProtected, ecKey)
	clientSigner := newOPKSSHCertSigner(t, compact, ecKey)
	clientConfig := &gossh.ClientConfig{
		User: "demo",
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(clientSigner),
		},
		HostKeyCallback: gossh.FixedHostKey(newPublicKey(t, keys.ServerHostKey.Public())),
	}

	client, err := upstream.Dial(clientConfig)
	require.NoError(t, err)
	defer client.Close()

	sess, err := client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	output, err := sess.CombinedOutput("whoami")
	require.NoError(t, err)
	assert.Regexp(t,
		`(?s)aud: "CLIENT_ID".*email: "fake\.user@example\.com".*iss: "https://mock-idp\..*".*sub: "sub-opkssh-es256"`,
		string(output),
	)
}

// buildCICProtected builds the base64url-encoded CIC protected header for the
// given SSH signing key. The caller uses this to compute the nonce commitment
// before minting the ID token, then passes the same value to buildOPKSSHCompact.
func buildCICProtected(t *testing.T, sshKey crypto.Signer) string {
	t.Helper()

	pubKey := sshKey.Public()
	jwk := jose.JSONWebKey{Key: pubKey}

	var alg string
	switch pubKey.(type) {
	case ed25519.PublicKey:
		alg = "EdDSA"
	case *ecdsa.PublicKey:
		alg = "ES256"
	default:
		t.Fatalf("unsupported key type for CIC: %T", pubKey)
	}

	rz := make([]byte, 32)
	_, err := rand.Read(rz)
	require.NoError(t, err)

	hdr, err := json.Marshal(map[string]any{
		"typ": "CIC",
		"alg": alg,
		"upk": jwk,
		"rz":  base64.RawURLEncoding.EncodeToString(rz),
	})
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(hdr)
}

// computeCICNonce returns the SHA3-256 commitment over the CIC protected header
// that the ID token nonce claim must carry.
func computeCICNonce(t *testing.T, cicProtected string) string {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(cicProtected)
	require.NoError(t, err)

	hash := sha3.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// buildOPKSSHCompact assembles a 5-segment compact PK Token with CIC binding.
// The ID token must have been minted with the nonce returned by computeCICNonce
// for the same cicProtected value.
func buildOPKSSHCompact(t *testing.T, idToken, cicProtected string, sshKey crypto.Signer) string {
	t.Helper()

	// Split the ID token JWS into OP segments.
	opParts := strings.Split(idToken, ".")
	require.Len(t, opParts, 3)
	payload, opProtected, opSig := opParts[1], opParts[0], opParts[2]

	// Sign the CIC manually. go-jose's signer creates its own protected
	// header, so we can't use it to produce a JWS with our custom CIC
	// header. Ed25519 uses raw 64-byte signatures; ECDSA uses IEEE P1363
	// (R||S padded to curve size). Both match go-jose's expected format.
	signingInput := []byte(cicProtected + "." + payload)

	var sig []byte
	switch k := sshKey.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, signingInput)
	case *ecdsa.PrivateKey:
		// go-jose uses IEEE P1363 encoding (R || S, each padded to curve size)
		// for ECDSA signatures, not ASN.1 DER.
		hash := sha256.Sum256(signingInput)
		r, s, err := ecdsa.Sign(rand.Reader, k, hash[:])
		require.NoError(t, err)
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		sig = make([]byte, 2*byteLen)
		r.FillBytes(sig[:byteLen])
		s.FillBytes(sig[byteLen:])
	default:
		t.Fatalf("unsupported key type for CIC signing: %T", sshKey)
	}
	cicSig := base64.RawURLEncoding.EncodeToString(sig)

	// Compact format: payload:opProtected:opSig:cicProtected:cicSig
	return payload + ":" + opProtected + ":" + opSig + ":" + cicProtected + ":" + cicSig
}

// newOPKSSHCertSigner builds a cert signer with the openpubkey-pkt extension
// set to the given compact PK Token, using the provided SSH key.
func newOPKSSHCertSigner(t *testing.T, compact string, sshKey crypto.Signer) gossh.Signer {
	t.Helper()

	signer := newSignerFromKey(t, sshKey)
	pub := newPublicKey(t, sshKey.Public())
	cert := &gossh.Certificate{
		Key:         pub,
		CertType:    gossh.UserCert,
		ValidAfter:  uint64(time.Now().Add(-1 * time.Minute).Unix()),
		ValidBefore: uint64(time.Now().Add(1 * time.Hour).Unix()),
		Permissions: gossh.Permissions{
			Extensions: map[string]string{
				"openpubkey-pkt": compact,
			},
		},
	}

	err := cert.SignCert(rand.Reader, signer)
	require.NoError(t, err)

	certSigner, err := gossh.NewCertSigner(cert, signer)
	require.NoError(t, err)
	return certSigner
}

// newOPKSSHCertSignerWithExtensions builds a cert signer with arbitrary extensions.
func newOPKSSHCertSignerWithExtensions(t *testing.T, extensions map[string]string) gossh.Signer {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := newSignerFromKey(t, key)
	pub := newPublicKey(t, key.Public())
	cert := &gossh.Certificate{
		Key:         pub,
		CertType:    gossh.UserCert,
		ValidAfter:  uint64(time.Now().Add(-1 * time.Minute).Unix()),
		ValidBefore: uint64(time.Now().Add(1 * time.Hour).Unix()),
		Permissions: gossh.Permissions{Extensions: extensions},
	}

	err = cert.SignCert(rand.Reader, signer)
	require.NoError(t, err)

	certSigner, err := gossh.NewCertSigner(cert, signer)
	require.NoError(t, err)
	return certSigner
}

type opksshEnv struct {
	env      testenv.Environment
	idp      *scenarios.IDP
	upstream upstreams.SSHUpstream
	keys     SSHKeys
	clientID string
}

// opksshTestEnv builds the standard opkssh test environment. When runtimeFlags
// is empty, opkssh is left disabled. When one or more runtime flags are
// supplied, the listener-global opkssh config is enabled and those flags are
// set on the environment.
func opksshTestEnv(t *testing.T, runtimeFlags ...config.RuntimeFlag) opksshEnv {
	t.Helper()

	const clientID = "CLIENT_ID"

	env := testenv.New(t)
	t.Cleanup(env.Stop)

	keys := NewSSHKeys(t)
	idp := scenarios.NewIDP([]*scenarios.User{{Email: "fake.user@example.com"}})
	env.Add(idp)
	env.Add(scenarios.SSH(scenarios.SSHConfig{
		HostKeys:  []any{keys.ServerHostKey},
		UserCAKey: keys.UserCAKey,
	}))
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if len(runtimeFlags) > 0 {
			if cfg.Options.RuntimeFlags == nil {
				cfg.Options.RuntimeFlags = map[config.RuntimeFlag]bool{}
			}
			cfg.Options.SSHOPKSSHEnabled = true
			cfg.Options.SSHOPKSSHIssuer = cfg.Options.ProviderURL
			cfg.Options.SSHOPKSSHClientIDs = []string{clientID}
			for _, runtimeFlag := range runtimeFlags {
				cfg.Options.RuntimeFlags[runtimeFlag] = true
			}
		}
	}))

	upstream := upstreams.SSH()
	upstream.Route().
		From(values.Const("ssh://example")).
		PPL(`{"allow":{"and":[{"authenticated_user":1}]}}`)
	env.AddUpstream(upstream)

	env.Start()
	snippets.WaitStartupComplete(env)
	return opksshEnv{env, idp, upstream, keys, clientID}
}

func opksshClientConfig(t *testing.T, certSigner gossh.Signer, keys SSHKeys) *gossh.ClientConfig {
	t.Helper()
	return &gossh.ClientConfig{
		User: "demo",
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(certSigner),
		},
		HostKeyCallback: gossh.FixedHostKey(newPublicKey(t, keys.ServerHostKey.Public())),
	}
}

func buildOPOnlyCompact(t *testing.T, idToken string) string {
	t.Helper()

	parts := strings.Split(idToken, ".")
	require.Len(t, parts, 3)
	return strings.Join([]string{parts[1], parts[0], parts[2]}, ":")
}

func sessionBindingIDForPublicKey(t *testing.T, publicKey any) string {
	t.Helper()

	sshPub := newPublicKey(t, publicKey)
	sum := sha256.Sum256(sshPub.Marshal())
	return "sshkey-SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func getSessionBinding(t *testing.T, env testenv.Environment, bindingID string) *sessionpb.SessionBinding {
	t.Helper()

	resp, err := env.NewDataBrokerServiceClient().Get(env.Context(), &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(&sessionpb.SessionBinding{}),
		Id:   bindingID,
	})
	require.NoError(t, err)

	binding := new(sessionpb.SessionBinding)
	require.NoError(t, resp.GetRecord().GetData().UnmarshalTo(binding))
	return binding
}

func getSession(t *testing.T, env testenv.Environment, sessionID string) *sessionpb.Session {
	t.Helper()

	resp, err := env.NewDataBrokerServiceClient().Get(env.Context(), &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(&sessionpb.Session{}),
		Id:   sessionID,
	})
	require.NoError(t, err)

	sess := new(sessionpb.Session)
	require.NoError(t, resp.GetRecord().GetData().UnmarshalTo(sess))
	return sess
}

func getUser(t *testing.T, env testenv.Environment, userID string) *userpb.User {
	t.Helper()

	resp, err := env.NewDataBrokerServiceClient().Get(env.Context(), &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(&userpb.User{}),
		Id:   userID,
	})
	require.NoError(t, err)

	user := new(userpb.User)
	require.NoError(t, resp.GetRecord().GetData().UnmarshalTo(user))
	return user
}

func TestOPKSSHNonOPKSSHCertFallsThrough(t *testing.T) {
	te := opksshTestEnv(t, config.RuntimeFlagSSHOPKSSH)

	// Build a cert WITHOUT the openpubkey-pkt extension. This should be
	// treated as a normal SSH cert, not an opkssh cert. Without a valid
	// session binding for this key, and no keyboard-interactive handler on the
	// client, the handshake should fail.
	certSigner := newOPKSSHCertSignerWithExtensions(t, map[string]string{
		"permit-pty": "",
	})

	_, err := te.upstream.Dial(opksshClientConfig(t, certSigner, te.keys))
	require.Error(t, err, "expected connection to fail when cert has no openpubkey-pkt extension")
}

func TestOPKSSHWrongAudience(t *testing.T) {
	te := opksshTestEnv(t, config.RuntimeFlagSSHOPKSSH)

	_, sshKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cicProtected := buildCICProtected(t, sshKey)
	nonce := computeCICNonce(t, cicProtected)

	// Mint a valid token but with a different audience than what Pomerium is configured to accept.
	idToken := te.idp.MintIDTokenWithNonce("WRONG_CLIENT_ID", "sub-test", "fake.user@example.com", nonce)
	compact := buildOPKSSHCompact(t, idToken, cicProtected, sshKey)
	certSigner := newOPKSSHCertSigner(t, compact, sshKey)

	_, err = te.upstream.Dial(opksshClientConfig(t, certSigner, te.keys))
	require.Error(t, err, "expected connection to fail when token audience doesn't match configured client IDs")
}

func TestOPKSSHExpiredToken(t *testing.T) {
	te := opksshTestEnv(t, config.RuntimeFlagSSHOPKSSH)

	_, sshKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cicProtected := buildCICProtected(t, sshKey)
	nonce := computeCICNonce(t, cicProtected)

	// Mint a token that is already expired.
	idToken := te.idp.MintExpiredIDTokenWithNonce(te.clientID, "sub-test", "fake.user@example.com", nonce)
	compact := buildOPKSSHCompact(t, idToken, cicProtected, sshKey)
	certSigner := newOPKSSHCertSigner(t, compact, sshKey)

	_, err = te.upstream.Dial(opksshClientConfig(t, certSigner, te.keys))
	require.Error(t, err, "expected connection to fail when ID token is expired")
}

func TestOPKSSHWrongIssuer(t *testing.T) {
	te := opksshTestEnv(t, config.RuntimeFlagSSHOPKSSH)

	_, sshKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cicProtected := buildCICProtected(t, sshKey)
	nonce := computeCICNonce(t, cicProtected)

	// Create a second, independent IDP. Its signing key is different from the
	// one Pomerium trusts. The token will fail JWKS verification.
	untrustedIDP := mockidp.New(mockidp.Config{})
	untrustedURL := untrustedIDP.Start(t)
	idToken := untrustedIDP.MintIDTokenWithNonce(untrustedURL, te.clientID, "sub-test", "fake.user@example.com", nonce)
	compact := buildOPKSSHCompact(t, idToken, cicProtected, sshKey)
	certSigner := newOPKSSHCertSigner(t, compact, sshKey)

	_, err = te.upstream.Dial(opksshClientConfig(t, certSigner, te.keys))
	require.Error(t, err, "expected connection to fail when token is signed by untrusted IDP")
}

func TestOPKSSHMalformedExtension(t *testing.T) {
	te := opksshTestEnv(t, config.RuntimeFlagSSHOPKSSH)

	// Put garbage in the openpubkey-pkt extension.
	certSigner := newOPKSSHCertSignerWithExtensions(t, map[string]string{
		"openpubkey-pkt": "this-is-not-a-valid-compact-token",
	})

	_, err := te.upstream.Dial(opksshClientConfig(t, certSigner, te.keys))
	require.Error(t, err, "expected connection to fail when openpubkey-pkt extension is malformed")
}

func TestOPKSSHDisabledByRuntimeFlag(t *testing.T) {
	// When SSHOPKSSHEnabled is true but RuntimeFlagSSHOPKSSH is not set,
	// config.Validate must reject the config. This is the primary gate
	// preventing accidental production enablement of the verifier.
	opts := config.NewDefaultOptions()
	opts.SSHAddr = ":22"
	opts.SSHOPKSSHEnabled = true
	opts.SSHOPKSSHIssuer = "https://accounts.example.test"
	opts.SSHOPKSSHClientIDs = []string{"pomerium-opkssh"}
	// Deliberately NOT setting RuntimeFlagSSHOPKSSH.
	err := opts.Validate()
	require.Error(t, err, "expected config validation to reject opkssh without runtime flag")
	assert.Contains(t, err.Error(), "runtime flag")

	// Additionally, verify that an environment without opkssh config does not
	// accept opkssh certs: a valid token in a cert falls through to session
	// lookup and fails without a keyboard-interactive handler.
	te := opksshTestEnv(t)

	_, sshKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cicProtected := buildCICProtected(t, sshKey)
	nonce := computeCICNonce(t, cicProtected)
	idToken := te.idp.MintIDTokenWithNonce(te.clientID, "sub-test", "fake.user@example.com", nonce)
	compact := buildOPKSSHCompact(t, idToken, cicProtected, sshKey)
	certSigner := newOPKSSHCertSigner(t, compact, sshKey)

	_, err = te.upstream.Dial(opksshClientConfig(t, certSigner, te.keys))
	require.Error(t, err, "expected connection to fail when opkssh is not configured")
}

func TestOPKSSHEnabledByDeprecatedRuntimeFlag(t *testing.T) {
	te := opksshTestEnv(t, config.RuntimeFlagSSHOPKSSHDraftUnsafe)

	_, sshKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cicProtected := buildCICProtected(t, sshKey)
	nonce := computeCICNonce(t, cicProtected)
	idToken := te.idp.MintIDTokenWithNonce(te.clientID, "deprecated-flag-sub", "fake.user@example.com", nonce)

	compact := buildOPKSSHCompact(t, idToken, cicProtected, sshKey)
	clientSigner := newOPKSSHCertSigner(t, compact, sshKey)

	client, err := te.upstream.Dial(opksshClientConfig(t, clientSigner, te.keys))
	require.NoError(t, err)
	defer client.Close()

	sess, err := client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	output, err := sess.CombinedOutput("whoami")
	require.NoError(t, err)
	assert.Contains(t, string(output), `sub: "deprecated-flag-sub"`)
}

func TestOPKSSHMissingCIC(t *testing.T) {
	te := opksshTestEnv(t, config.RuntimeFlagSSHOPKSSH)

	idToken := te.idp.MintIDTokenWithNonce(te.clientID, "missing-cic-sub", "fake.user@example.com", "nonce-without-cic")
	certSigner := newOPKSSHCertSigner(t, buildOPOnlyCompact(t, idToken), newSSHKey(t))

	_, err := te.upstream.Dial(opksshClientConfig(t, certSigner, te.keys))
	require.Error(t, err, "expected connection to fail when compact PK Token has no CIC segments")
}

func TestOPKSSHUserMergePreservesDeviceCredentialIDs(t *testing.T) {
	te := opksshTestEnv(t, config.RuntimeFlagSSHOPKSSH)

	const userSub = "user-merge-sub"

	_, err := databroker.Put(
		te.env.Context(),
		te.env.NewDataBrokerServiceClient(),
		&userpb.User{
			Id:                  userSub,
			Name:                "existing-name",
			DeviceCredentialIds: []string{"cred-1", "cred-2"},
		},
	)
	require.NoError(t, err)

	_, sshKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cicProtected := buildCICProtected(t, sshKey)
	nonce := computeCICNonce(t, cicProtected)
	idToken := te.idp.MintIDTokenWithNonce(te.clientID, userSub, "merged@example.test", nonce)
	certSigner := newOPKSSHCertSigner(t, buildOPKSSHCompact(t, idToken, cicProtected, sshKey), sshKey)

	client, err := te.upstream.Dial(opksshClientConfig(t, certSigner, te.keys))
	require.NoError(t, err)
	defer client.Close()

	sess, err := client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	_, err = sess.CombinedOutput("whoami")
	require.NoError(t, err)

	user := getUser(t, te.env, userSub)
	assert.ElementsMatch(t, []string{"cred-1", "cred-2"}, user.GetDeviceCredentialIds())
	assert.Equal(t, "merged@example.test", user.GetEmail())
}

func TestOPKSSHSessionRefreshDisabled(t *testing.T) {
	te := opksshTestEnv(t, config.RuntimeFlagSSHOPKSSH)

	const userSub = "refresh-disabled-sub"

	_, sshKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cicProtected := buildCICProtected(t, sshKey)
	nonce := computeCICNonce(t, cicProtected)
	idToken := te.idp.MintIDTokenWithNonce(te.clientID, userSub, "refresh@example.test", nonce)
	certSigner := newOPKSSHCertSigner(t, buildOPKSSHCompact(t, idToken, cicProtected, sshKey), sshKey)

	client, err := te.upstream.Dial(opksshClientConfig(t, certSigner, te.keys))
	require.NoError(t, err)
	defer client.Close()

	sess, err := client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	_, err = sess.CombinedOutput("whoami")
	require.NoError(t, err)

	bindingID := sessionBindingIDForPublicKey(t, sshKey.Public())
	binding := getSessionBinding(t, te.env, bindingID)
	sessionRecord := getSession(t, te.env, binding.GetSessionId())

	assert.Equal(t, userSub, sessionRecord.GetUserId())
	assert.ElementsMatch(t, []string{te.clientID}, sessionRecord.GetAudience())
	assert.True(t, sessionRecord.GetRefreshDisabled())
	assert.NotEmpty(t, sessionRecord.GetIdToken().GetRaw())
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
