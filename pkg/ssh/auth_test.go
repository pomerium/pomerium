package ssh

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestHandlePublicKeyMethodRequest(t *testing.T) {
	t.Run("no public key fingerprint", func(t *testing.T) {
		var a Auth
		var req extensions_ssh.PublicKeyMethodRequest
		_, err := a.handlePublicKeyMethodRequest(t.Context(), StreamAuthInfo{}, &req)
		assert.ErrorContains(t, err, "invalid public key fingerprint")
	})
	t.Run("evaluate error", func(t *testing.T) {
		info := StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		pe := func(context.Context, *Request) (*evaluator.Result, error) {
			return nil, errors.New("error evaluating policy")
		}
		a := NewAuth(t.Context(), fakePolicyEvaluator{evaluateSSH: pe}, nil, nil)
		_, err := a.handlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.ErrorContains(t, err, "error evaluating policy")
	})
	t.Run("allow", func(t *testing.T) {
		info := StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		fakePublicKey := []byte("fake-public-key")
		req.PublicKey = fakePublicKey
		pe := func(_ context.Context, r *Request) (*evaluator.Result, error) {
			assert.Equal(t, r, &Request{
				Username:  "username",
				Hostname:  "hostname",
				PublicKey: fakePublicKey,
				SessionID: "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY",
			})
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		a := NewAuth(t.Context(), fakePolicyEvaluator{evaluateSSH: pe}, nil, nil)
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.NoError(t, err)
		assert.Empty(t, res.RequireAdditionalMethods)
		require.NotNil(t, res.Allow)
		assert.Equal(t, res.Allow.PublicKey, fakePublicKey)
	})
	t.Run("deny", func(t *testing.T) {
		info := StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		pe := func(_ context.Context, _ *Request) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(true),
			}, nil
		}
		a := NewAuth(t.Context(), fakePolicyEvaluator{evaluateSSH: pe}, nil, nil)
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.NoError(t, err)
		assert.Nil(t, res.Allow)
		assert.Empty(t, res.RequireAdditionalMethods)
	})
	t.Run("public key unauthorized", func(t *testing.T) {
		info := StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		pe := func(_ context.Context, _ *Request) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(false, criteria.ReasonSSHPublickeyUnauthorized),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		a := NewAuth(t.Context(), fakePolicyEvaluator{evaluateSSH: pe}, nil, nil)
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.NoError(t, err)
		assert.Nil(t, res.Allow)
		assert.Equal(t, res.RequireAdditionalMethods, []string{MethodPublicKey})
	})
	t.Run("needs login", func(t *testing.T) {
		info := StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		pe := func(_ context.Context, _ *Request) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(false),
				Deny:  evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
			}, nil
		}
		a := NewAuth(t.Context(), fakePolicyEvaluator{evaluateSSH: pe}, nil, nil)
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.NoError(t, err)
		assert.NotNil(t, res.Allow)
		assert.Equal(t, res.RequireAdditionalMethods, []string{MethodKeyboardInteractive})
	})
	t.Run("internal command no session", func(t *testing.T) {
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, _ *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				return nil, status.Error(codes.NotFound, "not found")
			},
		}
		info := StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr(""),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		pe := func(_ context.Context, _ *Request) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(false),
				Deny:  evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
			}, nil
		}
		a := NewAuth(t.Context(), fakePolicyEvaluator{pe, client}, nil, nil)
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.NoError(t, err)
		assert.NotNil(t, res.Allow)
		assert.Equal(t, res.RequireAdditionalMethods, []string{MethodKeyboardInteractive})
	})
	t.Run("internal command with session", func(t *testing.T) {
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, _ *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				return &databroker.GetResponse{
					Record: &databroker.Record{
						Type: "type.googleapis.com/session.Session",
						Id:   "abc",
						Data: protoutil.NewAny(&session.Session{
							Id:     "abc",
							UserId: "USER-ID",
						}),
					},
				}, nil
			},
		}
		info := StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr(""),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		pe := func(_ context.Context, _ *Request) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		a := NewAuth(t.Context(), fakePolicyEvaluator{pe, client}, nil, nil)
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.NoError(t, err)
		assert.NotNil(t, res.Allow)
		assert.Empty(t, res.RequireAdditionalMethods)
	})
	t.Run("internal command databroker error", func(t *testing.T) {
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, _ *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				return nil, status.Error(codes.Unknown, "unknown")
			},
		}
		info := StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr(""),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		pe := func(_ context.Context, _ *Request) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		a := NewAuth(t.Context(), fakePolicyEvaluator{pe, client}, nil, nil)
		_, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.ErrorContains(t, err, "internal error")
	})
}

func TestHandleKeyboardInteractiveMethodRequest(t *testing.T) {
	t.Run("no public key", func(t *testing.T) {
		var a Auth
		_, err := a.handleKeyboardInteractiveMethodRequest(t.Context(), StreamAuthInfo{}, nil)
		assert.ErrorContains(t, err, "expected PublicKeyAllow message not to be nil")
	})
	t.Run("ok", func(t *testing.T) {
		pe := func(_ context.Context, _ *Request) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		var putRecords []*databroker.Record
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, _ *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				return nil, status.Error(codes.NotFound, "not found")
			},
			put: func(
				_ context.Context, in *databroker.PutRequest, _ ...grpc.CallOption,
			) (*databroker.PutResponse, error) {
				putRecords = append(putRecords, in.Records...)
				return &databroker.PutResponse{
					Records: in.Records,
				}, nil
			},
		}
		cfg := config.Config{
			Options: config.NewDefaultOptions(),
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: true})
		idpURL := mockIDP.Start(t)
		cfg.Options.Provider = "oidc"
		cfg.Options.ProviderURL = idpURL
		cfg.Options.ClientID = "client-id"
		cfg.Options.ClientSecret = "client-secret"
		a := NewAuth(t.Context(), fakePolicyEvaluator{pe, client}, atomicutil.NewValue(&cfg), nil)
		info := StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
			PublicKeyAllow: AuthMethodValue[extensions_ssh.PublicKeyAllowResponse]{
				Value: &extensions_ssh.PublicKeyAllowResponse{
					PublicKey: []byte("fake-public-key"),
				},
			},
			PublicKeyFingerprintSha256: []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
		}
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), info, nil, noopQuerier{})
		require.NoError(t, err)
		assert.NotNil(t, res.Allow)
		assert.Empty(t, res.RequireAdditionalMethods)

		// A new Session and User record should have been saved to the databroker.
		assert.Len(t, putRecords, 2)

		assert.Equal(t, "type.googleapis.com/user.User", putRecords[0].Type)
		assert.Equal(t, "fake.user@example.com", putRecords[0].Id)

		assert.Equal(t, "type.googleapis.com/session.Session", putRecords[1].Type)
		assert.Equal(t, "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY", putRecords[1].Id)
	})
	t.Run("denied", func(t *testing.T) {
		pe := func(_ context.Context, _ *Request) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(false),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, _ *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				return nil, status.Error(codes.NotFound, "not found")
			},
			put: func(
				_ context.Context, in *databroker.PutRequest, _ ...grpc.CallOption,
			) (*databroker.PutResponse, error) {
				return &databroker.PutResponse{
					Records: in.Records,
				}, nil
			},
		}
		cfg := config.Config{
			Options: config.NewDefaultOptions(),
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: true})
		idpURL := mockIDP.Start(t)
		cfg.Options.Provider = "oidc"
		cfg.Options.ProviderURL = idpURL
		cfg.Options.ClientID = "client-id"
		cfg.Options.ClientSecret = "client-secret"
		a := NewAuth(t.Context(), fakePolicyEvaluator{pe, client}, atomicutil.NewValue(&cfg), nil)
		info := StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
			PublicKeyAllow: AuthMethodValue[extensions_ssh.PublicKeyAllowResponse]{
				Value: &extensions_ssh.PublicKeyAllowResponse{
					PublicKey: []byte("fake-public-key"),
				},
			},
			PublicKeyFingerprintSha256: []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
		}
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), info, nil, noopQuerier{})
		require.NoError(t, err)
		assert.Nil(t, res.Allow)
		assert.Empty(t, res.RequireAdditionalMethods)
	})
	t.Run("invalid fingerprint", func(t *testing.T) {
		cfg := config.Config{
			Options: config.NewDefaultOptions(),
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: true})
		idpURL := mockIDP.Start(t)
		cfg.Options.Provider = "oidc"
		cfg.Options.ProviderURL = idpURL
		cfg.Options.ClientID = "client-id"
		cfg.Options.ClientSecret = "client-secret"
		a := NewAuth(t.Context(), nil, atomicutil.NewValue(&cfg), nil)
		info := StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
			PublicKeyAllow: AuthMethodValue[extensions_ssh.PublicKeyAllowResponse]{
				Value: &extensions_ssh.PublicKeyAllowResponse{
					PublicKey: []byte("fake-public-key"),
				},
			},
		}
		_, err := a.handleKeyboardInteractiveMethodRequest(t.Context(), info, noopQuerier{})
		assert.ErrorContains(t, err, "invalid public key fingerprint")
	})
}

func TestFormatSession(t *testing.T) {
	t.Run("invalid fingerprint", func(t *testing.T) {
		var a Auth
		info := StreamAuthInfo{
			PublicKeyFingerprintSha256: []byte("wrong-length"),
		}
		_, err := a.FormatSession(t.Context(), info)
		assert.ErrorContains(t, err, "invalid public key fingerprint")
	})
	t.Run("ok", func(t *testing.T) {
		exp := time.Now().Add(1 * time.Minute)
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, in *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				const expectedID = "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY"
				assert.Equal(t, in.Type, "type.googleapis.com/session.Session")
				assert.Equal(t, in.Id, expectedID)
				claims := identity.FlattenedClaims{
					"foo":  []any{"bar", "baz"},
					"quux": []any{42},
				}
				return &databroker.GetResponse{
					Record: &databroker.Record{
						Type: "type.googleapis.com/session.Session",
						Id:   expectedID,
						Data: protoutil.NewAny(&session.Session{
							Id:        expectedID,
							UserId:    "USER-ID",
							ExpiresAt: timestamppb.New(exp),
							Claims:    claims.ToPB(),
						}),
					},
				}, nil
			},
		}
		a := NewAuth(t.Context(), fakePolicyEvaluator{client: client}, nil, nil)
		info := StreamAuthInfo{
			PublicKeyFingerprintSha256: []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
		}
		b, err := a.FormatSession(t.Context(), info)
		assert.NoError(t, err)
		assert.Regexp(t, `
User ID:    USER-ID
Session ID: sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY
Expires at: .* \(in 1m0s\)
Claims:
  foo: \["bar", "baz"\]
  quux: 42
`[1:], string(b))
	})
}

func TestDeleteSession(t *testing.T) {
	t.Run("invalid fingerprint", func(t *testing.T) {
		var a Auth
		info := StreamAuthInfo{
			PublicKeyFingerprintSha256: []byte("wrong-length"),
		}
		err := a.DeleteSession(t.Context(), info)
		assert.ErrorContains(t, err, "invalid public key fingerprint")
	})
	t.Run("ok", func(t *testing.T) {
		putError := errors.New("sentinel")
		client := fakeDataBrokerServiceClient{
			put: func(
				_ context.Context, in *databroker.PutRequest, _ ...grpc.CallOption,
			) (*databroker.PutResponse, error) {
				require.Len(t, in.Records, 1)
				assert.Equal(t, in.Records[0].Id, "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY")
				assert.NotNil(t, in.Records[0].DeletedAt)
				return nil, putError
			},
		}
		a := NewAuth(t.Context(), fakePolicyEvaluator{client: client}, nil, nil)
		info := StreamAuthInfo{
			PublicKeyFingerprintSha256: []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
		}
		err := a.DeleteSession(t.Context(), info)
		assert.Equal(t, putError, err)
	})
}

type fakePolicyEvaluator struct {
	evaluateSSH func(context.Context, *Request) (*evaluator.Result, error)
	client      databroker.DataBrokerServiceClient
}

func (f fakePolicyEvaluator) EvaluateSSH(ctx context.Context, req *Request) (*evaluator.Result, error) {
	return f.evaluateSSH(ctx, req)
}

func (f fakePolicyEvaluator) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return f.client
}

func (f fakePolicyEvaluator) InvalidateCacheForRecords(_ context.Context, _ ...*databroker.Record) {}

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

type noopQuerier struct{}

func (noopQuerier) Prompt(
	_ context.Context, _ *extensions_ssh.KeyboardInteractiveInfoPrompts,
) (*extensions_ssh.KeyboardInteractiveInfoPromptResponses, error) {
	return nil, nil
}

func ptr[T any](t T) *T {
	return &t
}
