package ssh_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/code"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
)

type SSHKeys struct {
	// These keys are deterministically generated

	// ClientKey SSH client private key for authentication
	ClientKey ed25519.PrivateKey
	// ServerHostKey key for server identification
	ServerHostKey ed25519.PrivateKey
	// UpstreamHostKey for upstream identification
	UpstreamHostKey ed25519.PrivateKey
	// UserCAKey Certificate Authority key for signing user certificates
	UserCAKey ed25519.PrivateKey
	// ClientCAKey Certificate Authority key for signing client certificates
	ClientCAKey ed25519.PrivateKey

	// These keys are non-deterministically generated

	// ClientCASshPubKey Client CA public key in SSH wire format
	ClientCASshPubKey gossh.PublicKey
	// ClientSSHPubKey Client public key in SSH wire format
	ClientSSHPubKey gossh.PublicKey
}

func NewSSHKeys(t *testing.T) SSHKeys {
	t.Helper()

	s := SSHKeys{}
	s.ClientKey = newSSHKey(t)
	s.ServerHostKey = newSSHKey(t)

	s.UpstreamHostKey = newSSHKey(t)
	s.UserCAKey = newSSHKey(t)
	s.ClientCAKey = newSSHKey(t)

	var err error
	s.ClientSSHPubKey, err = gossh.NewPublicKey(s.ClientKey.Public())
	require.NoError(t, err)
	s.ClientCASshPubKey, err = gossh.NewPublicKey(s.ClientCAKey.Public())
	require.NoError(t, err)
	return s
}

// newSSHKey generates a new Ed25519 ssh key.
func newSSHKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return priv
}

// newSignerFromKey is a wrapper around ssh.NewSignerFromKey that will fail on error.
func newSignerFromKey(t *testing.T, key any) gossh.Signer {
	t.Helper()
	signer, err := gossh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

// newPublicKey is a wrapper around ssh.NewPublicKey that will fail on error.
func newPublicKey(t *testing.T, key any) gossh.PublicKey {
	t.Helper()
	sshkey, err := gossh.NewPublicKey(key)
	require.NoError(t, err)
	return sshkey
}

func VerifyWorkingShell(t *testing.T, client *gossh.Client) {
	t.Helper()
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

func RawFingerprintSHA256(pk gossh.PublicKey) []byte {
	return (*new(sha256.Sum256(pk.Marshal())))[:]
}

type fakePolicyEvaluator struct {
	evaluateSSH                      func(context.Context, uint64, ssh.AuthRequest) (*evaluator.Result, error)
	evaluateUpstreamTunnel           func(context.Context, ssh.AuthRequest, *config.Policy) (*evaluator.Result, error)
	evaluateAccessRequestArbitration func(context.Context, ssh.AuthRequest, *config.Policy) (*evaluator.Result, error)
	client                           databroker.DataBrokerServiceClient
}

// EvaluateUpstreamTunnel implements ssh.Evaluator.
func (f *fakePolicyEvaluator) EvaluateUpstreamTunnel(ctx context.Context, req ssh.AuthRequest, policy *config.Policy) (*evaluator.Result, error) {
	return f.evaluateUpstreamTunnel(ctx, req, policy)
}

// EvaluateUpstreamTunnel implements ssh.Evaluator.
func (f *fakePolicyEvaluator) EvaluateAccessRequestArbitration(ctx context.Context, req ssh.AuthRequest, policy *config.Policy) (*evaluator.Result, error) {
	return f.evaluateAccessRequestArbitration(ctx, req, policy)
}

func (f *fakePolicyEvaluator) EvaluateSSH(ctx context.Context, streamID uint64, req ssh.AuthRequest, _ bool) (*evaluator.Result, error) {
	return f.evaluateSSH(ctx, streamID, req)
}

func (f *fakePolicyEvaluator) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return f.client
}

func (f *fakePolicyEvaluator) InvalidateCacheForRecords(_ context.Context, _ ...*databroker.Record) {}

func staticFakePolicyEvaluator(result evaluator.Result, client databroker.DataBrokerServiceClient) *fakePolicyEvaluator {
	return &fakePolicyEvaluator{
		evaluateSSH: func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &result, nil
		},
		evaluateUpstreamTunnel: func(_ context.Context, _ ssh.AuthRequest, _ *config.Policy) (*evaluator.Result, error) {
			return &result, nil
		},
		evaluateAccessRequestArbitration: func(ctx context.Context, ar ssh.AuthRequest, p *config.Policy) (*evaluator.Result, error) {
			return &result, nil
		},
		client: client,
	}
}

var evalResultAlwaysAllow = evaluator.Result{
	Allow: evaluator.NewRuleResult(true),
	Deny:  evaluator.NewRuleResult(false),
}

// var evalResultPublicKeyAllow = evaluator.Result{
// 	Allow: evaluator.NewRuleResult(true, criteria.ReasonSSHPublickeyOK),
// 	Deny:  evaluator.NewRuleResult(true, criteria.ReasonUserUnauthenticated),
// }

// var evalResultPublicKeyUnauthorized = evaluator.Result{
// 	Allow: evaluator.NewRuleResult(false),
// 	Deny:  evaluator.NewRuleResult(true, criteria.ReasonSSHPublickeyUnauthorized),
// }

// var evalResultSessionUnauthenticated = evaluator.Result{
// 	Allow: evaluator.NewRuleResult(false),
// 	Deny:  evaluator.NewRuleResult(true, criteria.ReasonUserUnauthenticated),
// }

// var evalResultSessionUnauthorized = evaluator.Result{
// 	Allow: evaluator.NewRuleResult(false),
// 	Deny:  evaluator.NewRuleResult(true, criteria.ReasonUserUnauthorized),
// }

// var evalResultValidSession = evaluator.Result{
// 	Allow: evaluator.NewRuleResult(true, criteria.ReasonEmailOK),
// 	Deny:  evaluator.NewRuleResult(false),
// }

type fakeDataBrokerServiceClient struct {
	databroker.DataBrokerServiceClient

	get func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error)
	put func(ctx context.Context, in *databroker.PutRequest, opts ...grpc.CallOption) (*databroker.PutResponse, error)
}

func (f fakeDataBrokerServiceClient) Get(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
	return f.get(ctx, in, opts...)
}

func (f fakeDataBrokerServiceClient) Put(ctx context.Context, in *databroker.PutRequest, opts ...grpc.CallOption) (*databroker.PutResponse, error) {
	return f.put(ctx, in, opts...)
}

type noopQuerier struct {
	prompts []*extensions_ssh.KeyboardInteractiveInfoPrompts
}

func (q *noopQuerier) Prompt(
	_ context.Context, p *extensions_ssh.KeyboardInteractiveInfoPrompts,
) (*extensions_ssh.KeyboardInteractiveInfoPromptResponses, error) {
	q.prompts = append(q.prompts, p)
	return nil, nil
}

type fakeQuerier struct {
	prompt func(ctx context.Context, p *extensions_ssh.KeyboardInteractiveInfoPrompts) (*extensions_ssh.KeyboardInteractiveInfoPromptResponses, error)
}

func (q *fakeQuerier) Prompt(
	ctx context.Context, p *extensions_ssh.KeyboardInteractiveInfoPrompts,
) (*extensions_ssh.KeyboardInteractiveInfoPromptResponses, error) {
	return q.prompt(ctx, p)
}

type fakeIssuer struct {
	onCodeDecision func(ctx context.Context, id code.CodeID, c chan code.Status)
	associateCode  func(context.Context, code.CodeID, *session.SessionBindingRequest) (code.CodeID, error)
	ttl            time.Duration
	done           chan struct{} // can be nil to never cancel, or non-nil to allow canceling via close() out of band
}

var _ code.Issuer = (*fakeIssuer)(nil)

func (f *fakeIssuer) IssueCode() code.CodeID {
	return ""
}

func (f *fakeIssuer) CodeTTL() time.Duration {
	if f.ttl == 0 {
		return 1 * time.Minute
	}
	return f.ttl
}

func (f *fakeIssuer) AssociateCode(ctx context.Context, id code.CodeID, sbr *session.SessionBindingRequest) (code.CodeID, error) {
	if f.associateCode != nil {
		return f.associateCode(ctx, id, sbr)
	}
	return "associated-code", nil
}

func (f *fakeIssuer) OnCodeDecision(ctx context.Context, id code.CodeID) <-chan code.Status {
	ret := make(chan code.Status, 1)
	if f.onCodeDecision != nil {
		go f.onCodeDecision(ctx, id, ret)
	}
	return ret
}

func (f *fakeIssuer) Done() chan struct{} {
	return f.done
}

func (f *fakeIssuer) GetBindingRequest(context.Context, code.CodeID) (*session.SessionBindingRequest, bool) {
	return nil, false
}

func (f *fakeIssuer) GetSessionBindingsByUserID(context.Context, string) (map[string]*code.IdentitySessionPair, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeIssuer) RevokeCode(context.Context, code.CodeID) error {
	return fmt.Errorf("not implemented")
}

func (f *fakeIssuer) RevokeSessionBinding(context.Context, code.BindingID) error {
	return fmt.Errorf("not implemented")
}

func (f *fakeIssuer) RevokeSessionBindingBySession(context.Context, string) ([]*databroker.Record, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeIssuer) RevokeIdentityBinding(context.Context, code.BindingID) error {
	return fmt.Errorf("not implemented")
}
