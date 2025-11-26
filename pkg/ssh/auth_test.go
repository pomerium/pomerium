package ssh_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
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
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/code"
)

func TestHandlePublicKeyMethodRequest(t *testing.T) {
	t.Run("no public key fingerprint", func(t *testing.T) {
		var a ssh.Auth
		var req extensions_ssh.PublicKeyMethodRequest
		_, err := a.UnexportedHandlePublicKeyMethodRequest(t.Context(), ssh.StreamAuthInfo{}, &req)
		assert.ErrorContains(t, err, "invalid public key fingerprint")
	})
	t.Run("evaluate error", func(t *testing.T) {
		client := newValidGetClient()
		info := ssh.StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		pe := func(context.Context, uint64, ssh.AuthRequest) (*evaluator.Result, error) {
			return nil, errors.New("error evaluating policy")
		}
		a := ssh.NewAuth(fakePolicyEvaluator{evaluateSSH: pe, client: client}, nil, nil, &fakeIssuer{})
		_, err := a.UnexportedHandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.ErrorContains(t, err, "error evaluating policy")
	})
	t.Run("allow", func(t *testing.T) {
		client := newValidGetClient()
		info := ssh.StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		fakePublicKey := []byte{1, 2, 3, 4, 5, 6, 7}
		req.PublicKey = fakePublicKey
		pe := func(_ context.Context, _ uint64, r ssh.AuthRequest) (*evaluator.Result, error) {
			assert.Equal(t, r, ssh.AuthRequest{
				Username:         "username",
				Hostname:         "hostname",
				PublicKey:        string(fakePublicKey),
				SessionID:        "",
				SessionBindingID: "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY",
			})
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		a := ssh.NewAuth(fakePolicyEvaluator{evaluateSSH: pe, client: client}, nil, nil, &fakeIssuer{})
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.NoError(t, err)
		assert.Empty(t, res.RequireAdditionalMethods)
		require.NotNil(t, res.Allow)
		assert.Equal(t, res.Allow.PublicKey, fakePublicKey)
	})
	t.Run("deny", func(t *testing.T) {
		client := newValidGetClient()
		info := ssh.StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		pe := func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(true),
			}, nil
		}
		a := ssh.NewAuth(fakePolicyEvaluator{evaluateSSH: pe, client: client}, nil, nil, &fakeIssuer{})
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.NoError(t, err)
		assert.Nil(t, res.Allow)
		assert.Empty(t, res.RequireAdditionalMethods)
	})
	t.Run("public key unauthorized", func(t *testing.T) {
		client := newValidGetClient()
		info := ssh.StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		pe := func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(false, criteria.ReasonSSHPublickeyUnauthorized),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		a := ssh.NewAuth(fakePolicyEvaluator{evaluateSSH: pe, client: client}, nil, nil, &fakeIssuer{})
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.NoError(t, err)
		assert.Nil(t, res.Allow)
		assert.Equal(t, res.RequireAdditionalMethods, []string{ssh.MethodPublicKey})
	})

	t.Run("needs login", func(t *testing.T) {
		client := newValidGetClient()
		info := ssh.StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		pe := func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(false),
				Deny:  evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
			}, nil
		}
		a := ssh.NewAuth(fakePolicyEvaluator{evaluateSSH: pe, client: client}, nil, nil, &fakeIssuer{})
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.NoError(t, err)
		assert.NotNil(t, res.Allow)
		assert.Equal(t, res.RequireAdditionalMethods, []string{ssh.MethodKeyboardInteractive})
	})
	t.Run("internal command no session", func(t *testing.T) {
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, _ *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				return nil, status.Error(codes.NotFound, "not found")
			},
		}
		info := ssh.StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr(""),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		pe := func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(false),
				Deny:  evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
			}, nil
		}
		a := ssh.NewAuth(fakePolicyEvaluator{evaluateSSH: pe, client: client}, nil, nil, &fakeIssuer{})
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.NoError(t, err)
		assert.NotNil(t, res.Allow)
		assert.Equal(t, res.RequireAdditionalMethods, []string{ssh.MethodKeyboardInteractive})
	})
	t.Run("internal command with session", func(t *testing.T) {
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, r *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				switch r.Type {
				case "type.googleapis.com/session.Session":
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
				case "type.googleapis.com/session.SessionBinding":
					return &databroker.GetResponse{
						Record: &databroker.Record{
							Type: "type.googleapis.com/session.SessionBinding",
							Id:   "abc",
							Data: protoutil.NewAny(&session.SessionBinding{
								SessionId: "abc",
								UserId:    "USER-ID",
								ExpiresAt: timestamppb.New(time.Now().Add(time.Hour * 10000)),
								Protocol:  session.ProtocolSSH,
							}),
						},
					}, nil
				default:
					return nil, fmt.Errorf("unsupported type")
				}
			},
		}
		info := ssh.StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr(""),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		a := ssh.NewAuth(staticFakePolicyEvaluator(true, client), nil, nil, &fakeIssuer{})
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
		info := ssh.StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr(""),
		}
		var req extensions_ssh.PublicKeyMethodRequest
		req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
		a := ssh.NewAuth(staticFakePolicyEvaluator(true, client), nil, nil, &fakeIssuer{})
		_, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
		assert.ErrorContains(t, err, "internal error")
	})

	t.Run("unauthenticated", func(t *testing.T) {
		type testcase struct {
			retSessionBinding *session.SessionBinding
			retSession        *session.Session
			expectedResp      ssh.PublicKeyAuthMethodResponse
		}

		tcs := []testcase{
			// both not found
			{
				retSessionBinding: nil,
				retSession:        nil,
				expectedResp: ssh.PublicKeyAuthMethodResponse{
					RequireAdditionalMethods: []string{ssh.MethodKeyboardInteractive},
				},
			},
			// binding expired
			{
				retSessionBinding: &session.SessionBinding{
					ExpiresAt: timestamppb.New(time.Now().Add(-time.Minute)),
				},
				retSession: nil,
				expectedResp: ssh.PublicKeyAuthMethodResponse{
					RequireAdditionalMethods: []string{ssh.MethodKeyboardInteractive},
				},
			},
			// binding valid, but no such session
			{
				retSessionBinding: &session.SessionBinding{
					Protocol:  session.ProtocolSSH,
					ExpiresAt: timestamppb.New(time.Now().Add(time.Hour * 10000)),
				},
				retSession: nil,
				expectedResp: ssh.PublicKeyAuthMethodResponse{
					RequireAdditionalMethods: []string{ssh.MethodKeyboardInteractive},
				},
			},
		}

		for idx, tc := range tcs {
			client := fakeDataBrokerServiceClient{
				get: func(_ context.Context, in *databroker.GetRequest, _ ...grpc.CallOption) (*databroker.GetResponse, error) {
					switch in.Type {
					case "type.googleapis.com/session.SessionBinding":
						if tc.retSessionBinding == nil {
							return nil, status.Error(codes.NotFound, "not found")
						}
						return &databroker.GetResponse{
							Record: &databroker.Record{
								Type: grpcutil.GetTypeURL(tc.retSessionBinding),
								Data: protoutil.NewAny(tc.retSessionBinding),
							},
						}, nil
					case "type.googleapis.com/session.Session":
						if tc.retSession == nil {
							return nil, status.Error(codes.NotFound, "not found")
						}
						return &databroker.GetResponse{
							Record: &databroker.Record{
								Type: grpcutil.GetTypeURL(tc.retSession),
								Data: protoutil.NewAny(tc.retSession),
							},
						}, nil
					}
					return nil, fmt.Errorf("not implemented")
				},
			}

			info := ssh.StreamAuthInfo{
				Username: ptr("username"),
				Hostname: ptr(""),
			}
			var req extensions_ssh.PublicKeyMethodRequest
			req.PublicKeyFingerprintSha256 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
			a := ssh.NewAuth(staticFakePolicyEvaluator(true, client), nil, nil, &fakeIssuer{})
			resp, err := a.HandlePublicKeyMethodRequest(t.Context(), info, &req)
			assert.NoError(t, err, fmt.Sprintf("testcase %d failed", idx))
			assert.Equal(t, tc.expectedResp.RequireAdditionalMethods, resp.RequireAdditionalMethods, fmt.Sprintf("testcase %d failed", idx))
		}
	})
}

func TestHandleKeyboardInteractiveMethodRequest(t *testing.T) {
	t.Run("no public key", func(t *testing.T) {
		var a ssh.Auth
		_, err := a.UnexportedHandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamAuthInfo{}, nil)
		assert.ErrorContains(t, err, "expected PublicKeyAllow message not to be nil")
	})

	exampleAuthInfo := ssh.StreamAuthInfo{
		Username: ptr("username"),
		Hostname: ptr("hostname"),
		PublicKeyAllow: ssh.AuthMethodValue[extensions_ssh.PublicKeyAllowResponse]{
			Value: &extensions_ssh.PublicKeyAllowResponse{
				PublicKey: []byte("fake-public-key"),
			},
		},
		PublicKeyFingerprintSha256: []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
	}

	t.Run("stateless authenticate", func(t *testing.T) {
		cfg := config.Config{
			Options: config.NewDefaultOptions(),
		}
		var p atomic.Pointer[config.Config]
		p.Store(&cfg)

		a := ssh.NewAuth(nil, &p, nil, nil)
		_, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), exampleAuthInfo, nil, noopQuerier{})

		assert.ErrorContains(t, err, "ssh login is not currently enabled")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	})

	minimalConfig := func(idpURL string) *atomic.Pointer[config.Config] {
		cfg := config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.AuthenticateURLString = "https://pomerium.example.com"
		cfg.Options.Provider = "oidc"
		cfg.Options.ProviderURL = idpURL
		cfg.Options.ClientID = "client-id"
		cfg.Options.ClientSecret = "client-secret"
		var p atomic.Pointer[config.Config]
		p.Store(&cfg)
		return &p
	}

	t.Run("ok", func(t *testing.T) {
		bindingKey := "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY"
		sessionID := "some-opaque-id-set-by-idp"
		// var putRecords []*databroker.Record
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, r *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				switch r.Type {
				case "type.googleapis.com/session.SessionBinding":
					if r.Id == bindingKey {
						return &databroker.GetResponse{
								Record: &databroker.Record{
									Id:   "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY",
									Type: "type.googleapis.com/session.SessionBinding",
									Data: protoutil.NewAny(&session.SessionBinding{
										Protocol:  session.ProtocolSSH,
										UserId:    "fake.user@example.com",
										SessionId: sessionID,
										ExpiresAt: timestamppb.New(time.Now().Add(time.Hour * 100000)),
									}),
								},
							},
							nil
					}
					return nil, fmt.Errorf("not found")
				case "type.googleapis.com/session.Session":
					if r.Id == sessionID {
						return &databroker.GetResponse{
							Record: &databroker.Record{
								Id:   "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY",
								Type: "type.googleapis.com/session.SessionBinding",
								Data: protoutil.NewAny(&session.SessionBinding{
									Protocol:  session.ProtocolSSH,
									UserId:    "fake.user@example.com",
									SessionId: "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY",
								}),
							},
						}, nil
					}
					return nil, fmt.Errorf("not found")
				default:
					return nil, fmt.Errorf("type unsupported")
				}
			},
			put: func(_ context.Context, _ *databroker.PutRequest, _ ...grpc.CallOption) (*databroker.PutResponse, error) {
				return nil, fmt.Errorf("not implemented")
			},
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(staticFakePolicyEvaluator(true, client), minimalConfig(idpURL), nil, &fakeIssuer{
			state: &code.Status{
				BindingKey: "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY",
				State:      session.SessionBindingRequestState_Accepted,
				ExpiresAt:  time.Now().Add(time.Hour * 1000),
			},
		})
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), exampleAuthInfo, nil, noopQuerier{})
		require.NoError(t, err)
		assert.NotNil(t, res.Allow)
		assert.Empty(t, res.RequireAdditionalMethods)
	})

	t.Run("denied : code revoked", func(t *testing.T) {
		pe := func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(fakePolicyEvaluator{evaluateSSH: pe}, minimalConfig(idpURL), nil, &fakeIssuer{
			state: &code.Status{
				Code:       "",
				BindingKey: "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY",
				State:      session.SessionBindingRequestState_Revoked,
			},
		})
		_, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), exampleAuthInfo, nil, noopQuerier{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, st.Code().String(), codes.PermissionDenied.String())
	})

	t.Run("denied : no parent session", func(t *testing.T) {
		bindingKey := "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY"
		sessionID := "some-opaque-id-set-by-idp"
		// var putRecords []*databroker.Record
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, r *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				switch r.Type {
				case "type.googleapis.com/session.SessionBinding":
					if r.Id == bindingKey {
						return &databroker.GetResponse{
								Record: &databroker.Record{
									Id:   "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY",
									Type: "type.googleapis.com/session.SessionBinding",
									Data: protoutil.NewAny(&session.SessionBinding{
										Protocol:  session.ProtocolSSH,
										UserId:    "fake.user@example.com",
										SessionId: sessionID,
										ExpiresAt: timestamppb.New(time.Now().Add(time.Hour * 100000)),
									}),
								},
							},
							nil
					}
					return nil, fmt.Errorf("not found")
				case "type.googleapis.com/session.Session":
					return nil, fmt.Errorf("no matching session")
				default:
					return nil, fmt.Errorf("type unsupported")
				}
			},
			put: func(_ context.Context, _ *databroker.PutRequest, _ ...grpc.CallOption) (*databroker.PutResponse, error) {
				return nil, fmt.Errorf("not implemented")
			},
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(staticFakePolicyEvaluator(true, client), minimalConfig(idpURL), nil, &fakeIssuer{
			state: &code.Status{
				BindingKey: "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY",
				State:      session.SessionBindingRequestState_Accepted,
				ExpiresAt:  time.Now().Add(time.Hour * 1000),
			},
		})
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), exampleAuthInfo, nil, noopQuerier{})
		require.NoError(t, err)
		assert.Nil(t, res.Allow)
		assert.Empty(t, res.RequireAdditionalMethods)
	})

	t.Run("denied : not authorized", func(t *testing.T) {
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, _ *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				return &databroker.GetResponse{
					Record: &databroker.Record{
						Type: "type.googleapis.com/session.SessionBinding",
						Id:   "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY",
						Data: protoutil.NewAny(&session.SessionBinding{
							Protocol:  session.ProtocolSSH,
							ExpiresAt: timestamppb.New(time.Now().Add(time.Hour * 1000)),
						}),
					},
				}, nil
			},
			put: func(
				_ context.Context, in *databroker.PutRequest, _ ...grpc.CallOption,
			) (*databroker.PutResponse, error) {
				return &databroker.PutResponse{
					Records: in.Records,
				}, nil
			},
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(staticFakePolicyEvaluator(false, client), minimalConfig(idpURL), nil, &fakeIssuer{
			state: &code.Status{
				Code:       "",
				BindingKey: "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY",
				State:      session.SessionBindingRequestState_Accepted,
			},
		})
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), exampleAuthInfo, nil, noopQuerier{})
		require.NoError(t, err)
		assert.Nil(t, res.Allow)
		assert.Empty(t, res.RequireAdditionalMethods)
	})

	t.Run("invalid fingerprint", func(t *testing.T) {
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(nil, minimalConfig(idpURL), nil, &fakeIssuer{})
		info := ssh.StreamAuthInfo{
			Username: ptr("username"),
			Hostname: ptr("hostname"),
			PublicKeyAllow: ssh.AuthMethodValue[extensions_ssh.PublicKeyAllowResponse]{
				Value: &extensions_ssh.PublicKeyAllowResponse{
					PublicKey: []byte("fake-public-key"),
				},
			},
		}
		_, err := a.UnexportedHandleKeyboardInteractiveMethodRequest(t.Context(), info, noopQuerier{})
		assert.ErrorContains(t, err, "invalid public key fingerprint")
	})
}

func TestFormatSession(t *testing.T) {
	t.Run("invalid fingerprint", func(t *testing.T) {
		var a ssh.Auth
		info := ssh.StreamAuthInfo{
			PublicKeyFingerprintSha256: []byte("wrong-length"),
		}
		_, err := a.FormatSession(t.Context(), info)
		assert.ErrorContains(t, err, "invalid public key fingerprint")
	})
	t.Run("ok", func(t *testing.T) {
		// TODO : this also has to lookup session binding -> session
		exp := time.Now().Add(1 * time.Minute)
		sessionID := "some-opaque-id"
		userID := "USER-ID"
		claims := identity.FlattenedClaims{
			"foo":  []any{"bar", "baz"},
			"quux": []any{42},
		}
		const expectedID = "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY"
		client := fakeDataBrokerServiceClient{
			get: func(_ context.Context, r *databroker.GetRequest, _ ...grpc.CallOption) (*databroker.GetResponse, error) {
				switch r.Type {
				case "type.googleapis.com/session.Session":
					assert.Equal(t, sessionID, r.Id)
					return &databroker.GetResponse{
						Record: &databroker.Record{
							Type: "type.googleapis.com/session.Session",
							Id:   sessionID,
							Data: protoutil.NewAny(&session.Session{
								Id:        sessionID,
								UserId:    userID,
								ExpiresAt: timestamppb.New(exp),
								Claims:    claims.ToPB(),
							}),
						},
					}, nil
				case "type.googleapis.com/session.SessionBinding":
					assert.Equal(t, expectedID, r.Id)
					return &databroker.GetResponse{
						Record: &databroker.Record{
							Id:   expectedID,
							Type: "type.googleapis.com/session.SessionBinding",
							Data: protoutil.NewAny(&session.SessionBinding{
								Protocol:  session.ProtocolSSH,
								SessionId: sessionID,
								ExpiresAt: timestamppb.New(exp),
							}),
						},
					}, nil
				default:
					return nil, fmt.Errorf("type unsupported")
				}
			},
		}
		a := ssh.NewAuth(fakePolicyEvaluator{client: client}, nil, nil, &fakeIssuer{})
		info := ssh.StreamAuthInfo{
			PublicKeyFingerprintSha256: []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
		}
		b, err := a.FormatSession(t.Context(), info)
		assert.NoError(t, err)
		assert.Regexp(t, fmt.Sprintf(`
User ID:    %s
Session ID: %s
Expires at: .*
Claims:
  foo: \["bar", "baz"\]
  quux: 42
`, userID, sessionID)[1:], string(b))
	})
}

func TestDeleteSession(t *testing.T) {
	t.Run("invalid fingerprint", func(t *testing.T) {
		var a ssh.Auth
		info := ssh.StreamAuthInfo{
			PublicKeyFingerprintSha256: []byte("wrong-length"),
		}
		err := a.DeleteSession(t.Context(), info)
		assert.ErrorContains(t, err, "invalid public key fingerprint")
	})

	t.Run("ok", func(t *testing.T) {
		putError := errors.New("sentinel")
		const bindingID = "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY"
		const sessionID = "session-id-1"
		client := fakeDataBrokerServiceClient{
			get: func(_ context.Context, r *databroker.GetRequest, _ ...grpc.CallOption) (*databroker.GetResponse, error) {
				switch r.Type {
				case "type.googleapis.com/session.Session":
					assert.Equal(t, sessionID, r.Id)
					return &databroker.GetResponse{
						Record: &databroker.Record{
							Id:   sessionID,
							Type: "type.googleapis.com/session.Session",
							Data: protoutil.NewAny(&session.Session{
								Id:        sessionID,
								ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
							}),
						},
					}, nil
				case "type.googleapis.com/session.SessionBinding":
					assert.Equal(t, bindingID, r.Id)
					return &databroker.GetResponse{
						Record: &databroker.Record{
							Id:   bindingID,
							Type: "type.googleapis.com/session.SessionBinding",
							Data: protoutil.NewAny(&session.SessionBinding{
								Protocol:  session.ProtocolSSH,
								SessionId: sessionID,
								ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
							}),
						},
					}, nil
				default:
					return nil, fmt.Errorf("type unsupported")
				}
			},
			put: func(
				_ context.Context, in *databroker.PutRequest, _ ...grpc.CallOption,
			) (*databroker.PutResponse, error) {
				require.Len(t, in.Records, 1)
				assert.Equal(t, in.Records[0].Id, sessionID)
				assert.NotNil(t, in.Records[0].DeletedAt)
				return nil, putError
			},
		}
		a := ssh.NewAuth(fakePolicyEvaluator{client: client}, nil, nil, &fakeIssuer{})
		info := ssh.StreamAuthInfo{
			PublicKeyFingerprintSha256: []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
		}
		err := a.DeleteSession(t.Context(), info)
		assert.ErrorIs(t, err, putError)
	})
}

type fakePolicyEvaluator struct {
	evaluateSSH            func(context.Context, uint64, ssh.AuthRequest) (*evaluator.Result, error)
	evaluateUpstreamTunnel func(context.Context, ssh.AuthRequest, *config.Policy) (*evaluator.Result, error)
	client                 databroker.DataBrokerServiceClient
}

// EvaluateUpstreamTunnel implements ssh.Evaluator.
func (f fakePolicyEvaluator) EvaluateUpstreamTunnel(ctx context.Context, req ssh.AuthRequest, policy *config.Policy) (*evaluator.Result, error) {
	return f.evaluateUpstreamTunnel(ctx, req, policy)
}

func (f fakePolicyEvaluator) EvaluateSSH(ctx context.Context, streamID uint64, req ssh.AuthRequest, _ bool) (*evaluator.Result, error) {
	return f.evaluateSSH(ctx, streamID, req)
}

func (f fakePolicyEvaluator) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return f.client
}

func (f fakePolicyEvaluator) InvalidateCacheForRecords(_ context.Context, _ ...*databroker.Record) {}

func staticFakePolicyEvaluator(allow bool, client databroker.DataBrokerServiceClient) fakePolicyEvaluator {
	return fakePolicyEvaluator{
		evaluateSSH: func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(allow),
				Deny:  evaluator.NewRuleResult(!allow),
			}, nil
		},
		evaluateUpstreamTunnel: func(_ context.Context, _ ssh.AuthRequest, _ *config.Policy) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(allow),
				Deny:  evaluator.NewRuleResult(!allow),
			}, nil
		},
		client: client,
	}
}

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

type fakeIssuer struct {
	state *code.Status
}

var _ code.Issuer = (*fakeIssuer)(nil)

func (f *fakeIssuer) IssueCode() code.CodeID {
	return ""
}

func (f *fakeIssuer) AssociateCode(context.Context, code.CodeID, *session.SessionBindingRequest) (code.CodeID, error) {
	return "", nil
}

func (f *fakeIssuer) OnCodeDecision(context.Context, code.CodeID) <-chan code.Status {
	ret := make(chan code.Status, 1)
	if f.state != nil {
		go func() {
			ret <- *f.state
		}()
	}
	return ret
}

func (f *fakeIssuer) Done() chan struct{} {
	return nil
}

func (f *fakeIssuer) GetBindingRequest(context.Context, code.CodeID) (*session.SessionBindingRequest, bool) {
	return nil, false
}

func (f *fakeIssuer) GetSessionByUserID(context.Context, string) (map[string]*code.IdentitySessionPair, error) {
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

func newValidGetClient() databroker.DataBrokerServiceClient {
	return fakeDataBrokerServiceClient{
		get: func(
			_ context.Context, in *databroker.GetRequest, _ ...grpc.CallOption,
		) (*databroker.GetResponse, error) {
			switch in.Type {
			case "type.googleapis.com/session.Session":
				return &databroker.GetResponse{
					Record: &databroker.Record{
						Type: "type.googleapis.com/session.Session",
						Data: protoutil.NewAny(&session.Session{}),
					},
				}, nil
			case "type.googleapis.com/session.SessionBinding":
				return &databroker.GetResponse{
					Record: &databroker.Record{
						Type: "type.googleapis.com/session.SessionBinding",
						Data: protoutil.NewAny(&session.SessionBinding{
							Protocol:  session.ProtocolSSH,
							ExpiresAt: timestamppb.New(time.Now().Add(time.Hour * 1000)),
						}),
					},
				}, nil
			}
			return nil, status.Error(codes.NotFound, "not found")
		},
	}
}
