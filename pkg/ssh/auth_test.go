package ssh_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	nooptrace "go.opentelemetry.io/otel/trace/noop"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
	"github.com/pomerium/pomerium/pkg/identity/oidc/google"
	"github.com/pomerium/pomerium/pkg/identity/oidc/hosted"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/api"
	"github.com/pomerium/pomerium/pkg/ssh/code"
)

func sessionBindingIDFromPublicKey(key gossh.PublicKey) string {
	fp, err := ssh.UnexportedSessionIDFromFingerprint(RawFingerprintSHA256(key))
	if err != nil {
		panic(err)
	}
	return fp
}

func newPkMethodRequest(key gossh.PublicKey) *extensions_ssh.PublicKeyMethodRequest {
	return &extensions_ssh.PublicKeyMethodRequest{
		PublicKey:                  key.Marshal(),
		PublicKeyAlg:               key.Type(),
		PublicKeyFingerprintSha256: RawFingerprintSHA256(key),
	}
}

func newPkAuthContextUpdates(key gossh.PublicKey) *extensions_ssh.AuthContext {
	return &extensions_ssh.AuthContext{
		PublicKey:                  key.Marshal(),
		PublicKeyAlg:               key.Type(),
		PublicKeyFingerprintSha256: RawFingerprintSHA256(key),
	}
}

func TestInitialPublicKeyRequestWithNoSession(t *testing.T) {
	user := mustNewUserRequest(t, "username", "hostname")
	sshKey1 := newPublicKey(t, newSSHKey(t).Public())
	sshKey2 := newPublicKey(t, newSSHKey(t).Public())

	databrokerClient := fakeDataBrokerServiceClient{
		get: func(context.Context, *databroker.GetRequest, ...grpc.CallOption) (*databroker.GetResponse, error) {
			return nil, status.Error(codes.NotFound, "not found")
		},
	}

	t.Run("no session found", func(t *testing.T) {
		evaluator := &fakePolicyEvaluator{
			evaluateSSH: func(_ context.Context, _ uint64, r ssh.AuthRequest) (*evaluator.Result, error) {
				assert.Equal(t, ssh.AuthRequest{
					Username:        "username",
					Hostname:        "hostname",
					PublicKey:       string(sshKey1.Marshal()),
					LogOnlyIfDenied: true,
				}, r)
				return &evaluator.Result{
					Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
					Deny:  evaluator.NewRuleResult(false),
				}, nil
			},
			client: databrokerClient,
		}

		a := ssh.NewAuth(evaluator, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, newPkMethodRequest(sshKey1))
		assert.NoError(t, err)
		assert.Equal(t, ssh.AuthMethodResponse{
			AllowMethod:            true,
			NextRequiredAuthMethod: ssh.MethodKeyboardInteractive,
			ContextUpdates:         newPkAuthContextUpdates(sshKey1),
		}, res)
	})

	t.Run("error during evaluation", func(t *testing.T) {
		evaluator := &fakePolicyEvaluator{
			evaluateSSH: func(context.Context, uint64, ssh.AuthRequest) (*evaluator.Result, error) {
				return nil, errors.New("test error")
			},
			client: databrokerClient,
		}

		a := ssh.NewAuth(evaluator, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		// Use the unexported version, since by default most errors are converted to
		// a generic "internal error"
		res, err := a.UnexportedHandlePublicKeyMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, newPkMethodRequest(sshKey1))
		assert.ErrorContains(t, err, "test error")
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
	})

	t.Run("public key unauthorized", func(t *testing.T) {
		evaluator := &fakePolicyEvaluator{
			evaluateSSH: func(_ context.Context, _ uint64, r ssh.AuthRequest) (*evaluator.Result, error) {
				assert.True(t, r.LogOnlyIfDenied)
				assert.Equal(t, "username", r.Username)
				assert.Equal(t, "hostname", r.Hostname)
				if r.PublicKey != string(sshKey2.Marshal()) {
					return &evaluator.Result{
						Allow: evaluator.NewRuleResult(false, criteria.ReasonSSHPublickeyUnauthorized),
						Deny:  evaluator.NewRuleResult(true),
					}, nil
				}
				return &evaluator.Result{
					Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
					Deny:  evaluator.NewRuleResult(true),
				}, nil
			},
			client: databrokerClient,
		}

		a := ssh.NewAuth(evaluator, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		res, err := a.UnexportedHandlePublicKeyMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, newPkMethodRequest(sshKey1))
		assert.NoError(t, err)
		assert.Equal(t, ssh.AuthMethodResponse{
			AllowMethod:            false,
			NextRequiredAuthMethod: ssh.MethodPublicKey,
		}, res)

		res, err = a.UnexportedHandlePublicKeyMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, newPkMethodRequest(sshKey2))
		assert.NoError(t, err)
		assert.Equal(t, ssh.AuthMethodResponse{
			AllowMethod:            true,
			NextRequiredAuthMethod: ssh.MethodKeyboardInteractive,
			ContextUpdates:         newPkAuthContextUpdates(sshKey2),
		}, res)
	})

	t.Run("source IP denied", func(t *testing.T) {
		evaluator := &fakePolicyEvaluator{
			evaluateSSH: func(context.Context, uint64, ssh.AuthRequest) (*evaluator.Result, error) {
				return &evaluator.Result{
					Allow: evaluator.NewRuleResult(false, criteria.ReasonSourceIPUnauthorized),
					Deny:  evaluator.NewRuleResult(false),
				}, nil
			},
			client: databrokerClient,
		}

		a := ssh.NewAuth(evaluator, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, newPkMethodRequest(sshKey1))
		assert.NoError(t, err)
		// non-retriable
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
	})

	t.Run("ssh username denied", func(t *testing.T) {
		evaluator := &fakePolicyEvaluator{
			evaluateSSH: func(context.Context, uint64, ssh.AuthRequest) (*evaluator.Result, error) {
				return &evaluator.Result{
					Allow: evaluator.NewRuleResult(false, criteria.ReasonSSHUsernameUnauthorized),
					Deny:  evaluator.NewRuleResult(false),
				}, nil
			},
			client: databrokerClient,
		}

		a := ssh.NewAuth(evaluator, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, newPkMethodRequest(sshKey1))
		assert.NoError(t, err)
		// non-retriable
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
	})

	t.Run("bad evaluator response", func(t *testing.T) {
		evaluator := &fakePolicyEvaluator{
			evaluateSSH: func(_ context.Context, _ uint64, r ssh.AuthRequest) (*evaluator.Result, error) {
				// the evaluator should only allow requests that are missing session IDs
				// if the hostname is empty
				require.NotEmpty(t, r.Hostname)
				require.Empty(t, r.SessionBindingID)
				require.Empty(t, r.SessionID)
				return &evaluator.Result{
					Allow: evaluator.NewRuleResult(true),
					Deny:  evaluator.NewRuleResult(false),
				}, nil
			},
			client: databrokerClient,
		}

		a := ssh.NewAuth(evaluator, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		assert.Panics(t, func() {
			_, _ = a.HandlePublicKeyMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, newPkMethodRequest(sshKey1))
		})
	})

	t.Run("invalid fingerprint in request", func(t *testing.T) {
		evaluator := &fakePolicyEvaluator{
			evaluateSSH: func(context.Context, uint64, ssh.AuthRequest) (*evaluator.Result, error) {
				return &evaluator.Result{
					Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
					Deny:  evaluator.NewRuleResult(false),
				}, nil
			},
			client: databrokerClient,
		}

		a := ssh.NewAuth(evaluator, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		for _, fp := range [][]byte{{}, []byte("invalid")} {
			res, err := a.UnexportedHandlePublicKeyMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, &extensions_ssh.PublicKeyMethodRequest{
				PublicKey:                  sshKey1.Marshal(),
				PublicKeyAlg:               sshKey1.Type(),
				PublicKeyFingerprintSha256: fp,
			})
			assert.ErrorContains(t, err, "invalid public key fingerprint")
			assert.Equal(t, ssh.AuthMethodResponse{}, res)
		}
	})
}

func TestInitialPublicKeyRequestWithExistingValidSession(t *testing.T) {
	user := mustNewUserRequest(t, "username", "hostname")
	sshKey1 := newPublicKey(t, newSSHKey(t).Public())
	sessionID := uuid.NewString()
	userID := "user"

	sessionBindingID := sessionBindingIDFromPublicKey(sshKey1)
	databrokerClient := fakeDataBrokerServiceClient{
		get: func(_ context.Context, in *databroker.GetRequest, _ ...grpc.CallOption) (*databroker.GetResponse, error) {
			switch in.Type {
			case "type.googleapis.com/session.SessionBinding":
				assert.Equal(t, sessionBindingID, in.Id)
				return &databroker.GetResponse{
					Record: &databroker.Record{
						Type: "type.googleapis.com/session.SessionBinding",
						Data: protoutil.NewAny(&session.SessionBinding{
							Protocol:  session.ProtocolSSH,
							IssuedAt:  timestamppb.New(time.Now().Add(-1 * time.Minute)),
							ExpiresAt: timestamppb.New(time.Now().Add(time.Hour * 1000)),
							SessionId: sessionID,
							UserId:    userID,
						}),
					},
				}, nil
			case "type.googleapis.com/session.Session":
				assert.Equal(t, sessionID, in.Id)
				return &databroker.GetResponse{
					Record: &databroker.Record{
						Type: "type.googleapis.com/session.Session",
						Data: protoutil.NewAny(&session.Session{
							Id:     sessionID,
							UserId: userID,
						}),
					},
				}, nil
			}
			panic("unreachable")
		},
	}

	t.Run("session is valid", func(t *testing.T) {
		evaluator := &fakePolicyEvaluator{
			evaluateSSH: func(_ context.Context, _ uint64, r ssh.AuthRequest) (*evaluator.Result, error) {
				assert.Equal(t, "username", r.Username)
				assert.Equal(t, "hostname", r.Hostname)
				assert.Equal(t, string(sshKey1.Marshal()), r.PublicKey)
				if r.SessionBindingID == "" || r.SessionID == "" {
					assert.True(t, r.LogOnlyIfDenied)
					return &evaluator.Result{
						Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
						Deny:  evaluator.NewRuleResult(false),
					}, nil
				}
				assert.Equal(t, sessionBindingID, r.SessionBindingID)
				assert.Equal(t, sessionID, r.SessionID)
				return &evaluator.Result{
					Allow: evaluator.NewRuleResult(true, criteria.ReasonUserOK),
					Deny:  evaluator.NewRuleResult(false),
				}, nil
			},
			client: databrokerClient,
		}
		a := ssh.NewAuth(evaluator, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, newPkMethodRequest(sshKey1))
		require.NoError(t, err)
		assert.Equal(t, ssh.AuthMethodResponse{
			AllowMethod:              true,
			NoFurtherMethodsRequired: true,
			ContextUpdates: &extensions_ssh.AuthContext{
				PublicKey:                  sshKey1.Marshal(),
				PublicKeyAlg:               sshKey1.Type(),
				PublicKeyFingerprintSha256: RawFingerprintSHA256(sshKey1),
				SessionId:                  sessionID,
				UserId:                     userID,
				SessionBindingId:           sessionBindingID,
			},
		}, res)
	})

	t.Run("session exists but is invalid", func(t *testing.T) {
		evaluator := &fakePolicyEvaluator{
			evaluateSSH: func(_ context.Context, _ uint64, r ssh.AuthRequest) (*evaluator.Result, error) {
				assert.Equal(t, "username", r.Username)
				assert.Equal(t, "hostname", r.Hostname)
				assert.Equal(t, string(sshKey1.Marshal()), r.PublicKey)
				if r.SessionBindingID == "" || r.SessionID == "" {
					assert.True(t, r.LogOnlyIfDenied)
					return &evaluator.Result{
						Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
						Deny:  evaluator.NewRuleResult(false),
					}, nil
				}
				assert.Equal(t, sessionBindingID, r.SessionBindingID)
				assert.Equal(t, sessionID, r.SessionID)
				return &evaluator.Result{
					// ReasonUserUnauthenticated triggers the login flow
					Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
					Deny:  evaluator.NewRuleResult(false),
				}, nil
			},
			client: databrokerClient,
		}
		a := ssh.NewAuth(evaluator, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		res, err := a.HandlePublicKeyMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, newPkMethodRequest(sshKey1))
		require.NoError(t, err)
		assert.Equal(t, ssh.AuthMethodResponse{
			AllowMethod:            true,
			NextRequiredAuthMethod: ssh.MethodKeyboardInteractive,
			ContextUpdates: &extensions_ssh.AuthContext{
				PublicKey:                  sshKey1.Marshal(),
				PublicKeyAlg:               sshKey1.Type(),
				PublicKeyFingerprintSha256: RawFingerprintSHA256(sshKey1),
			},
		}, res)
	})

	t.Run("session exists but evaluation fails", func(t *testing.T) {
		evaluator := &fakePolicyEvaluator{
			evaluateSSH: func(_ context.Context, _ uint64, r ssh.AuthRequest) (*evaluator.Result, error) {
				if r.SessionBindingID == "" || r.SessionID == "" {
					return &evaluator.Result{
						Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
						Deny:  evaluator.NewRuleResult(false),
					}, nil
				}
				return nil, errors.New("test error")
			},
			client: databrokerClient,
		}
		a := ssh.NewAuth(evaluator, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		res, err := a.UnexportedHandlePublicKeyMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, newPkMethodRequest(sshKey1))
		require.ErrorContains(t, err, "test error")
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
	})

	t.Run("session is valid but user is unauthorized", func(t *testing.T) {
		// there are several ways this can occur
		results := []*evaluator.Result{
			{ // allow is false
				Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthorized),
				Deny:  evaluator.NewRuleResult(false),
			},
			{ // deny is true and reason isn't ReasonSSHAccessRequestRequired
				Allow: evaluator.NewRuleResult(true, criteria.ReasonUserOK),
				Deny:  evaluator.NewRuleResult(true, criteria.ReasonClaimUnauthorized),
			},
		}

		for i, result := range results {
			t.Run(fmt.Sprintf("result %d", i), func(t *testing.T) {
				evaluator := &fakePolicyEvaluator{
					evaluateSSH: func(_ context.Context, _ uint64, r ssh.AuthRequest) (*evaluator.Result, error) {
						if r.SessionBindingID == "" || r.SessionID == "" {
							return &evaluator.Result{
								Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
								Deny:  evaluator.NewRuleResult(false),
							}, nil
						}
						return result, nil
					},
					client: databrokerClient,
				}
				a := ssh.NewAuth(evaluator, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
				res, err := a.UnexportedHandlePublicKeyMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, newPkMethodRequest(sshKey1))
				require.NoError(t, err)
				assert.Equal(t, ssh.AuthMethodResponse{}, res)
			})
		}
	})

	t.Run("session or session binding records missing or invalid", func(t *testing.T) {
		type testcase struct {
			retSessionBinding     *databroker.Record
			retSession            *databroker.Record
			expectedErrorContains string
		}

		tcs := []testcase{
			// both not found
			{
				retSessionBinding: nil,
				retSession:        nil,
			},
			// binding expired
			{
				retSessionBinding: &databroker.Record{
					Type: "type.googleapis.com/session.SessionBinding",
					Data: protoutil.NewAny(&session.SessionBinding{
						ExpiresAt: timestamppb.New(time.Now().Add(-time.Minute)),
					}),
				},
				retSession: nil,
			},
			// binding valid, but no such session
			{
				retSessionBinding: &databroker.Record{
					Type: "type.googleapis.com/session.SessionBinding",
					Data: protoutil.NewAny(&session.SessionBinding{
						Protocol:  session.ProtocolSSH,
						ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
					}),
				},
				retSession: nil,
			},
			// binding valid, but wrong protocol
			{
				retSessionBinding: &databroker.Record{
					Type: "type.googleapis.com/session.SessionBinding",
					Data: protoutil.NewAny(&session.SessionBinding{
						Protocol:  "not-ssh",
						ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
					}),
				},
				retSession:            nil,
				expectedErrorContains: "invalid protocol",
			},
			// binding deleted
			{
				retSessionBinding: &databroker.Record{
					Type: "type.googleapis.com/session.SessionBinding",
					Data: protoutil.NewAny(&session.SessionBinding{
						Protocol:  session.ProtocolSSH,
						ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
					}),
					DeletedAt: timestamppb.Now(),
				},
				retSession: nil,
			},
			// binding valid, but session deleted
			{
				retSessionBinding: &databroker.Record{
					Type: "type.googleapis.com/session.SessionBinding",
					Data: protoutil.NewAny(&session.SessionBinding{
						Protocol:  session.ProtocolSSH,
						ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
					}),
				},
				retSession: &databroker.Record{
					Type: "type.googleapis.com/session.Session",
					Data: protoutil.NewAny(&session.Session{
						ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
					}),
					DeletedAt: timestamppb.Now(),
				},
			},
			// binding valid, but session expired
			{
				retSessionBinding: &databroker.Record{
					Type: "type.googleapis.com/session.SessionBinding",
					Data: protoutil.NewAny(&session.SessionBinding{
						Protocol:  session.ProtocolSSH,
						ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
					}),
				},
				retSession: &databroker.Record{
					Type: "type.googleapis.com/session.Session",
					Data: protoutil.NewAny(&session.Session{
						ExpiresAt: timestamppb.New(time.Now().Add(-time.Hour)),
					}),
				},
			},
			// binding has wrong data type
			{
				retSessionBinding: &databroker.Record{
					Type: "type.googleapis.com/session.SessionBinding",
					Data: protoutil.NewAny(&wrapperspb.StringValue{Value: "not a session binding"}),
				},
				retSession:            nil,
				expectedErrorContains: "mismatched message type",
			},
			// binding valid, but session has wrong data type
			{
				retSessionBinding: &databroker.Record{
					Type: "type.googleapis.com/session.SessionBinding",
					Data: protoutil.NewAny(&session.SessionBinding{
						Protocol:  session.ProtocolSSH,
						ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
					}),
				},
				retSession: &databroker.Record{
					Type: "type.googleapis.com/session.Session",
					Data: protoutil.NewAny(&wrapperspb.StringValue{Value: "not a session"}),
				},
				expectedErrorContains: "mismatched message type",
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
							Record: tc.retSessionBinding,
						}, nil
					case "type.googleapis.com/session.Session":
						if tc.retSession == nil {
							return nil, status.Error(codes.NotFound, "not found")
						}
						return &databroker.GetResponse{
							Record: tc.retSession,
						}, nil
					}
					return nil, fmt.Errorf("not implemented")
				},
			}

			user := mustNewUserRequest(t, "username", "")

			req := newPkMethodRequest(sshKey1)
			a := ssh.NewAuth(&fakePolicyEvaluator{
				evaluateSSH: func(_ context.Context, _ uint64, ar ssh.AuthRequest) (*evaluator.Result, error) {
					if ar.SessionBindingID == "" || ar.SessionID == "" {
						return &evaluator.Result{
							Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
							Deny:  evaluator.NewRuleResult(false),
						}, nil
					}
					return &evaluator.Result{
						Allow: evaluator.NewRuleResult(true),
						Deny:  evaluator.NewRuleResult(false),
					}, nil
				},
				client: client,
			}, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
			resp, err := a.UnexportedHandlePublicKeyMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, req)
			if tc.expectedErrorContains != "" {
				require.ErrorContains(t, err, tc.expectedErrorContains, fmt.Sprintf("testcase %d failed", idx))
				assert.Equal(t, ssh.AuthMethodResponse{}, resp)
			} else {
				require.NoError(t, err, fmt.Sprintf("testcase %d failed", idx))
				// the response should always be the same for each case, if there is no error
				assert.Equal(t, ssh.AuthMethodResponse{
					AllowMethod:            true,
					NextRequiredAuthMethod: ssh.MethodKeyboardInteractive,
					ContextUpdates:         newPkAuthContextUpdates(sshKey1),
				}, resp)
			}
		}
	})
}

func TestKeyboardInteractiveLoginRequest(t *testing.T) {
	user := mustNewUserRequest(t, "username", "hostname")
	route := config.Policy{
		From:             "ssh://hostname",
		To:               mustParseWeightedURLs(t, "ssh://dest"),
		ShowErrorDetails: true,
	}
	sshKey1 := newPublicKey(t, newSSHKey(t).Public())
	sessionBindingID := sessionBindingIDFromPublicKey(sshKey1)
	initialAuthContext := func() *extensions_ssh.AuthContext {
		return &extensions_ssh.AuthContext{
			PublicKey:                  sshKey1.Marshal(),
			PublicKeyAlg:               sshKey1.Type(),
			PublicKeyFingerprintSha256: RawFingerprintSHA256(sshKey1),
		}
	}

	t.Run("public key info missing", func(t *testing.T) {
		cfg := config.New(config.NewDefaultOptions())
		var p atomic.Pointer[config.Config]
		p.Store(cfg)

		a := ssh.NewAuth(nil, &p, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		assert.Panics(t, func() {
			_, _ = a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{}, user, nil, &noopQuerier{})
		})
	})
	t.Run("stateless authenticate", func(t *testing.T) {
		cfg := config.New(config.NewDefaultOptions())
		cfg.Options.Policies = append(cfg.Options.Policies, route)
		var p atomic.Pointer[config.Config]
		p.Store(cfg)

		a := ssh.NewAuth(nil, &p, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		_, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, &noopQuerier{})

		assert.ErrorContains(t, err, "ssh login is not currently enabled")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	})

	minimalConfig := func(idpURL string) *atomic.Pointer[config.Config] {
		cfg := config.New(config.NewDefaultOptions())
		cfg.Options.AuthenticateURLString = "https://pomerium.example.com"
		// Also set an internal authenticate service URL, in order to verify
		// that the sign-in link uses the external URL, not this one.
		cfg.Options.AuthenticateInternalURLString = "https://localhost:1234"
		cfg.Options.Provider = "oidc"
		cfg.Options.ProviderURL = idpURL
		cfg.Options.ClientID = "client-id"
		cfg.Options.ClientSecret = "client-secret"
		cfg.Options.Policies = append(cfg.Options.Policies, route)

		var p atomic.Pointer[config.Config]
		p.Store(cfg)
		return &p
	}

	t.Run("invalid fingerprint", func(t *testing.T) {
		a := ssh.NewAuth(staticFakePolicyEvaluator(evalResultAlwaysAllow, nil), minimalConfig("https://unused"), &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		_, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{
			PublicKey:                  sshKey1.Marshal(),
			PublicKeyAlg:               sshKey1.Type(),
			PublicKeyFingerprintSha256: []byte("bad fingerprint"),
		}, user, nil, &noopQuerier{})

		assert.ErrorContains(t, err, "invalid public key fingerprint")
	})

	t.Run("ShowErrorDetails disabled", func(t *testing.T) {
		cfg := minimalConfig("https://unused")
		cfg.Load().Options.Policies[0].ShowErrorDetails = false
		a := ssh.NewAuth(staticFakePolicyEvaluator(evalResultAlwaysAllow, nil), cfg, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		_, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{
			PublicKey:                  sshKey1.Marshal(),
			PublicKeyAlg:               sshKey1.Type(),
			PublicKeyFingerprintSha256: []byte("bad fingerprint"),
		}, user, nil, &noopQuerier{})

		assert.Equal(t, status.Error(codes.PermissionDenied, "permission denied").Error(), err.Error())
	})

	t.Run("invalid authentiate config", func(t *testing.T) {
		p := minimalConfig("https://unused")
		p.Load().Options.AuthenticateURLString = "invalid url"
		a := ssh.NewAuth(staticFakePolicyEvaluator(evalResultAlwaysAllow, nil), p, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		_, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, &noopQuerier{})

		assert.ErrorContains(t, err, "url does not contain a valid scheme")
	})

	validRecordsClient := func(sessionID string) fakeDataBrokerServiceClient {
		return fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, r *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				switch r.Type {
				case "type.googleapis.com/session.SessionBinding":
					if r.Id == sessionBindingID {
						return &databroker.GetResponse{
								Record: &databroker.Record{
									Id:   sessionBindingID,
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
								Id:   sessionID,
								Type: "type.googleapis.com/session.Session",
								Data: protoutil.NewAny(&session.Session{
									UserId:    "fake.user@example.com",
									ExpiresAt: timestamppb.New(time.Now().Add(time.Hour * 100000)),
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
	}
	t.Run("ok", func(t *testing.T) {
		sessionID := "some-opaque-id-set-by-idp"
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(staticFakePolicyEvaluator(evalResultAlwaysAllow, validRecordsClient(sessionID)), minimalConfig(idpURL), &nooptrace.TracerProvider{}, &fakeIssuer{
			onCodeDecision: func(_ context.Context, id code.CodeID, c chan code.Status) {
				c <- code.Status{
					Code:       string(id),
					BindingKey: sessionBindingID,
					State:      session.SessionBindingRequestState_Accepted,
					ExpiresAt:  time.Now().Add(time.Hour * 1000),
				}
			},
		}, nil)
		querier := &noopQuerier{}
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, querier)
		require.NoError(t, err)
		if assert.Len(t, querier.prompts, 1, "expected to receive a sign-in prompt") {
			assert.Equal(t, "https://pomerium.example.com/.pomerium/sign_in?user_code=associated-code",
				querier.prompts[0].Instruction)
		}

		assert.Equal(t, ssh.AuthMethodResponse{
			AllowMethod:              true,
			NoFurtherMethodsRequired: true,
			ContextUpdates: &extensions_ssh.AuthContext{
				SessionBindingId: sessionBindingID,
				SessionId:        sessionID,
				UserId:           "fake.user@example.com",
			},
		}, res)
	})

	t.Run("error evaluating session after login", func(t *testing.T) {
		sessionID := "some-opaque-id-set-by-idp"
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(&fakePolicyEvaluator{
			evaluateSSH: func(_ context.Context, _ uint64, ar ssh.AuthRequest) (*evaluator.Result, error) {
				if ar.SessionID == "" || ar.SessionBindingID == "" {
					return &evaluator.Result{
						Allow: evaluator.NewRuleResult(true),
						Deny:  evaluator.NewRuleResult(false),
					}, nil
				}
				return nil, fmt.Errorf("error evaluating session")
			},
			client: validRecordsClient(sessionID),
		}, minimalConfig(idpURL), &nooptrace.TracerProvider{}, &fakeIssuer{
			onCodeDecision: func(_ context.Context, id code.CodeID, c chan code.Status) {
				c <- code.Status{
					Code:       string(id),
					BindingKey: sessionBindingID,
					State:      session.SessionBindingRequestState_Accepted,
					ExpiresAt:  time.Now().Add(time.Hour * 1000),
				}
			},
		}, nil)
		querier := &noopQuerier{}
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, querier)
		assert.ErrorContains(t, err, "error evaluating session")
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
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
		a := ssh.NewAuth(&fakePolicyEvaluator{evaluateSSH: pe}, minimalConfig(idpURL), &nooptrace.TracerProvider{}, &fakeIssuer{
			onCodeDecision: func(_ context.Context, id code.CodeID, c chan code.Status) {
				c <- code.Status{
					Code:       string(id),
					BindingKey: sessionBindingID,
					State:      session.SessionBindingRequestState_Revoked,
				}
			},
		}, nil)
		resp, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, &noopQuerier{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, st.Code().String(), codes.PermissionDenied.String())
		assert.Equal(t, ssh.AuthMethodResponse{}, resp)
	})

	t.Run("denied : code issuer canceled", func(t *testing.T) {
		pe := func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		done := make(chan struct{})
		a := ssh.NewAuth(&fakePolicyEvaluator{evaluateSSH: pe}, minimalConfig(idpURL), &nooptrace.TracerProvider{}, &fakeIssuer{
			done: done,
			onCodeDecision: func(_ context.Context, _ code.CodeID, _ chan code.Status) {
				close(done)
			},
		}, nil)
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, &noopQuerier{})
		require.ErrorContains(t, err, "code issuer can no longer process this request")
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
	})

	t.Run("denied : request canceled by user", func(t *testing.T) {
		pe := func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(&fakePolicyEvaluator{evaluateSSH: pe}, minimalConfig(idpURL), &nooptrace.TracerProvider{}, &fakeIssuer{
			onCodeDecision: func(_ context.Context, _ code.CodeID, c chan code.Status) {
				close(c)
			},
		}, nil)
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, &noopQuerier{})
		require.ErrorContains(t, err, "authentication request cancelled by user")
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
	})

	t.Run("denied : session binding expires", func(t *testing.T) {
		pe := func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(&fakePolicyEvaluator{evaluateSSH: pe}, minimalConfig(idpURL), &nooptrace.TracerProvider{}, &fakeIssuer{
			ttl: 1 * time.Millisecond,
		}, nil)
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, &noopQuerier{})
		require.ErrorContains(t, err, "authentication request timeout")
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
	})

	t.Run("denied : code status does not match request binding key", func(t *testing.T) {
		pe := func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(&fakePolicyEvaluator{evaluateSSH: pe}, minimalConfig(idpURL), &nooptrace.TracerProvider{}, &fakeIssuer{
			onCodeDecision: func(_ context.Context, id code.CodeID, c chan code.Status) {
				c <- code.Status{
					Code:       string(id),
					BindingKey: "not the same binding key",
					State:      session.SessionBindingRequestState_Accepted,
				}
			},
		}, nil)
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, &noopQuerier{})
		require.ErrorContains(t, err, "mismatched binding keys")
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
	})

	t.Run("code issuer sends invalid status", func(t *testing.T) {
		pe := func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(&fakePolicyEvaluator{evaluateSSH: pe}, minimalConfig(idpURL), &nooptrace.TracerProvider{}, &fakeIssuer{
			onCodeDecision: func(_ context.Context, id code.CodeID, c chan code.Status) {
				c <- code.Status{
					Code:       string(id),
					BindingKey: sessionBindingID,
					State:      session.SessionBindingRequestState_InFlight, // invalid
				}
			},
		}, nil)
		assert.Panics(t, func() {
			_, _ = a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, &noopQuerier{})
		})
	})

	t.Run("error while prompting user", func(t *testing.T) {
		pe := func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(&fakePolicyEvaluator{evaluateSSH: pe}, minimalConfig(idpURL), &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, &fakeQuerier{
			prompt: func(context.Context, *extensions_ssh.KeyboardInteractiveInfoPrompts) (*extensions_ssh.KeyboardInteractiveInfoPromptResponses, error) {
				return nil, fmt.Errorf("test prompt error")
			},
		})
		require.ErrorContains(t, err, "test prompt error")
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
	})

	t.Run("error associating code", func(t *testing.T) {
		pe := func(_ context.Context, _ uint64, _ ssh.AuthRequest) (*evaluator.Result, error) {
			return &evaluator.Result{
				Allow: evaluator.NewRuleResult(true),
				Deny:  evaluator.NewRuleResult(false),
			}, nil
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(&fakePolicyEvaluator{evaluateSSH: pe}, minimalConfig(idpURL), &nooptrace.TracerProvider{}, &fakeIssuer{
			associateCode: func(context.Context, code.CodeID, *session.SessionBindingRequest) (code.CodeID, error) {
				return "", fmt.Errorf("test associate code error")
			},
		}, nil)
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, &noopQuerier{})
		require.ErrorContains(t, err, "failed to associate a code to this session")
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
	})

	t.Run("denied : error retrieving parent session", func(t *testing.T) {
		sessionID := "some-opaque-id-set-by-idp"
		// var putRecords []*databroker.Record
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, r *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				switch r.Type {
				case "type.googleapis.com/session.SessionBinding":
					if r.Id == sessionBindingID {
						return &databroker.GetResponse{
								Record: &databroker.Record{
									Id:   sessionBindingID,
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
					// if the code is not NotFound it will prevent any retries looking up
					// the session
					return nil, fmt.Errorf("test error")
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
		a := ssh.NewAuth(staticFakePolicyEvaluator(evalResultAlwaysAllow, client), minimalConfig(idpURL), &nooptrace.TracerProvider{}, &fakeIssuer{
			onCodeDecision: func(_ context.Context, id code.CodeID, c chan code.Status) {
				c <- code.Status{
					Code:       string(id),
					BindingKey: sessionBindingID,
					State:      session.SessionBindingRequestState_Accepted,
					ExpiresAt:  time.Now().Add(time.Hour * 1000),
				}
			},
		}, nil)
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, &noopQuerier{})
		require.ErrorContains(t, err, "test error")
		require.Equal(t, codes.Internal, status.Code(err))
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
	})

	t.Run("denied : session record lookup timeout", func(t *testing.T) {
		sessionID := "some-opaque-id-set-by-idp"
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, r *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				switch r.Type {
				case "type.googleapis.com/session.SessionBinding":
					if r.Id == sessionBindingID {
						return &databroker.GetResponse{
								Record: &databroker.Record{
									Id:   sessionBindingID,
									Type: "type.googleapis.com/session.SessionBinding",
									Data: protoutil.NewAny(&session.SessionBinding{
										Protocol:  session.ProtocolSSH,
										UserId:    "fake.user@example.com",
										SessionId: sessionID,
										ExpiresAt: timestamppb.New(time.Now().Add(time.Hour * 1000)),
									}),
								},
							},
							nil
					}
					return nil, fmt.Errorf("not found")
				case "type.googleapis.com/session.Session":
					return nil, status.Errorf(codes.NotFound, "not found")
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
		a := ssh.NewAuth(staticFakePolicyEvaluator(evalResultAlwaysAllow, client), minimalConfig(idpURL), &nooptrace.TracerProvider{}, &fakeIssuer{
			onCodeDecision: func(_ context.Context, id code.CodeID, c chan code.Status) {
				c <- code.Status{
					Code:       string(id),
					BindingKey: sessionBindingID,
					State:      session.SessionBindingRequestState_Accepted,
					ExpiresAt:  time.Now().Add(time.Hour * 1000),
				}
			},
			ttl: 1 * time.Second, // short ttl since this tests a backoff timeout
		}, nil)
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, &noopQuerier{})
		require.ErrorContains(t, err, "failed to get matching session binding: context deadline exceeded")
		require.Equal(t, codes.Internal, status.Code(err))
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
	})

	t.Run("denied : not authorized", func(t *testing.T) {
		client := fakeDataBrokerServiceClient{
			get: func(
				_ context.Context, r *databroker.GetRequest, _ ...grpc.CallOption,
			) (*databroker.GetResponse, error) {
				switch r.Type {
				case "type.googleapis.com/session.SessionBinding":
					return &databroker.GetResponse{
						Record: &databroker.Record{
							Type: "type.googleapis.com/session.SessionBinding",
							Id:   sessionBindingID,
							Data: protoutil.NewAny(&session.SessionBinding{
								Protocol:  session.ProtocolSSH,
								ExpiresAt: timestamppb.New(time.Now().Add(time.Hour * 1000)),
								SessionId: "fake-session-id",
								UserId:    "fake-user-id",
							}),
						},
					}, nil
				case "type.googleapis.com/session.Session":
					return &databroker.GetResponse{
						Record: &databroker.Record{
							Id:   "fake-session-id",
							Type: "type.googleapis.com/session.Session",
							Data: protoutil.NewAny(&session.Session{
								UserId:    "fake.user@example.com",
								ExpiresAt: timestamppb.New(time.Now().Add(time.Hour * 1000)),
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
				return &databroker.PutResponse{
					Records: in.Records,
				}, nil
			},
		}
		mockIDP := mockidp.New(mockidp.Config{EnableDeviceAuth: false})
		idpURL := mockIDP.Start(t)
		a := ssh.NewAuth(staticFakePolicyEvaluator(evaluator.Result{
			Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthorized),
			Deny:  evaluator.NewRuleResult(false),
		}, client), minimalConfig(idpURL), &nooptrace.TracerProvider{}, &fakeIssuer{
			onCodeDecision: func(_ context.Context, id code.CodeID, c chan code.Status) {
				c <- code.Status{
					Code:       string(id),
					BindingKey: sessionBindingID,
					State:      session.SessionBindingRequestState_Accepted,
				}
			},
		}, nil)
		res, err := a.HandleKeyboardInteractiveMethodRequest(t.Context(), ssh.StreamInfo{}, initialAuthContext(), user, nil, &noopQuerier{})
		require.NoError(t, err)
		assert.Equal(t, ssh.AuthMethodResponse{}, res)
	})
}

func TestFormatSession(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		// TODO : this also has to lookup session binding -> session
		exp := time.Now().Add(1 * time.Minute)
		sessionID := "some-opaque-id"
		userID := "USER-ID"
		claims := identity.FlattenedClaims{
			"foo":  []any{"bar", "baz"},
			"quux": []any{42},
		}
		const bindingID = "sshkey-SHA256:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY"
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
					assert.Equal(t, bindingID, r.Id)
					return &databroker.GetResponse{
						Record: &databroker.Record{
							Id:   bindingID,
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
		a := ssh.NewAuth(&fakePolicyEvaluator{client: client}, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		b, err := a.GetSession(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{
			SessionBindingId: bindingID,
			SessionId:        sessionID,
		})
		assert.NoError(t, err)
		assert.Regexp(t, fmt.Sprintf(`
User ID:    %s
Session ID: %s
Expires at: .*
Claims:
  foo: \["bar", "baz"\]
  quux: 42
`, userID, sessionID)[1:], string(b.Format()))
	})
}

func TestDeleteSession(t *testing.T) {
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
		a := ssh.NewAuth(&fakePolicyEvaluator{client: client}, nil, &nooptrace.TracerProvider{}, &fakeIssuer{}, nil)
		err := a.DeleteSession(t.Context(), ssh.StreamInfo{}, &extensions_ssh.AuthContext{
			// Note: this used to work using only the fingerprint in the auth context,
			// but now the session binding ID is always available directly if there is
			// a valid session.
			// PublicKeyFingerprintSha256: []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
			SessionBindingId: bindingID,
			SessionId:        sessionID,
		})
		assert.ErrorIs(t, err, putError)
	})
}

func TestSignInPrompt(t *testing.T) {
	t.Run("hosted", func(t *testing.T) {
		var priv [ed25519.PrivateKeySize]byte
		authenticator, err := hosted.New(t.Context(), &oauth.Options{
			ProviderURL:  "http://example.com",
			ClientSecret: base64.RawStdEncoding.EncodeToString(priv[:]),
		})
		require.NoError(t, err)
		assert.Equal(t, "Please sign in to continue", ssh.SignInPrompt(authenticator))
	})
	t.Run("oidc", func(t *testing.T) {
		authenticator, err := oidc.New(t.Context(), &oauth.Options{
			ProviderURL: "http://example.com",
		})
		require.NoError(t, err)
		assert.Equal(t, "Please sign in to continue", ssh.SignInPrompt(authenticator))
	})
	t.Run("google", func(t *testing.T) {
		authenticator, err := google.New(t.Context(), &oauth.Options{})
		require.NoError(t, err)
		assert.Equal(t, "Please sign in with google to continue", ssh.SignInPrompt(authenticator))
	})
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

func mustNewUserRequest(t *testing.T, username, hostname string) api.UserRequest {
	u, err := api.NewUserRequest(username, hostname)
	require.NoError(t, err)
	return u
}

func TestSocketAddressFromString(t *testing.T) {
	t.Run("valid target", func(t *testing.T) {
		expected := &corev3.SocketAddress{
			Address: "0.0.0.0",
			PortSpecifier: &corev3.SocketAddress_PortValue{
				PortValue: uint32(22),
			},
		}
		actual := ssh.SocketAddressFromString(&config.Policy{
			To: mustParseWeightedURLs(t, "ssh://0.0.0.0:22"),
		})

		assert.Empty(t, cmp.Diff(expected, actual, protocmp.Transform()))
	})

	t.Run("partial target", func(t *testing.T) {
		expected := &corev3.SocketAddress{
			Address: "0.0.0.0",
		}
		actual := ssh.SocketAddressFromString(&config.Policy{
			To: []config.WeightedURL{
				{
					URL: url.URL{
						Host: "0.0.0.0",
					},
				},
			},
		})
		assert.Empty(t, cmp.Diff(expected, actual, protocmp.Transform()))
	})

	t.Run("no hostport target", func(t *testing.T) {
		expected := &corev3.SocketAddress{}
		actual := ssh.SocketAddressFromString(&config.Policy{
			To: []config.WeightedURL{
				{
					URL: url.URL{
						Scheme: "aaa",
					},
				},
			},
		})
		assert.NotNil(t, actual)
		assert.Empty(t, cmp.Diff(expected, actual, protocmp.Transform()))
	})

	t.Run("empty target", func(t *testing.T) {
		actual := ssh.SocketAddressFromString(&config.Policy{
			To: []config.WeightedURL{},
		})
		assert.Nil(t, actual)
	})
}
