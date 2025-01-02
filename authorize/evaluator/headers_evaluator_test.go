package evaluator

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/storage"
)

func BenchmarkHeadersEvaluator(b *testing.B) {
	ctx := context.Background()

	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(b, err)
	encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(b, err)
	privateJWK, err := cryptutil.PrivateJWKFromBytes(encodedSigningKey)
	require.NoError(b, err)
	iat := time.Unix(1686870680, 0)

	ctx = storage.WithQuerier(ctx, storage.NewStaticQuerier([]proto.Message{
		&session.Session{Id: "s1", ImpersonateSessionId: proto.String("s2"), UserId: "u1"},
		&session.Session{Id: "s2", UserId: "u2", Claims: map[string]*structpb.ListValue{
			"name": {Values: []*structpb.Value{
				structpb.NewStringValue("n1"),
			}},
		}, IssuedAt: timestamppb.New(iat)},
		&user.User{Id: "u2", Name: "USER#2"},
		newDirectoryUserRecord(directory.User{ID: "u2", GroupIDs: []string{"g1", "g2", "g3", "g4"}}),
		newDirectoryGroupRecord(directory.Group{ID: "g1", Name: "GROUP1"}),
		newDirectoryGroupRecord(directory.Group{ID: "g2", Name: "GROUP2"}),
		newDirectoryGroupRecord(directory.Group{ID: "g3", Name: "GROUP3"}),
		newDirectoryGroupRecord(directory.Group{ID: "g4", Name: "GROUP4"}),
	}...))

	s := store.New()
	s.UpdateJWTClaimHeaders(config.NewJWTClaimHeaders("email", "groups", "user", "CUSTOM_KEY"))
	s.UpdateSigningKey(privateJWK)

	e := NewHeadersEvaluator(s)

	req := &HeadersRequest{
		EnableRoutingKey:              true,
		Issuer:                        "from.example.com",
		Audience:                      "from.example.com",
		KubernetesServiceAccountToken: "KUBERNETES_SERVICE_ACCOUNT_TOKEN",
		ToAudience:                    "to.example.com",
		Session: RequestSession{
			ID: "s1",
		},
		SetRequestHeaders: map[string]string{
			"X-Custom-Header":         "CUSTOM_VALUE",
			"X-ID-Token":              "${pomerium.id_token}",
			"X-Access-Token":          "${pomerium.access_token}",
			"Client-Cert-Fingerprint": "${pomerium.client_cert_fingerprint}",
			"Authorization":           "Bearer ${pomerium.jwt}",
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := e.Evaluate(ctx, req, rego.EvalTime(iat))
		require.NoError(b, err)
		_ = res
	}
}

func TestNewHeadersRequestFromPolicy(t *testing.T) {
	req, _ := NewHeadersRequestFromPolicy(&config.Policy{
		EnableGoogleCloudServerlessAuthentication: true,
		From: "https://*.example.com",
		To: config.WeightedURLs{
			{
				URL: *mustParseURL("http://to.example.com"),
			},
		},
	}, RequestHTTP{
		Hostname: "from.example.com",
		ClientCertificate: ClientCertificateInfo{
			Leaf: "--- FAKE CERTIFICATE ---",
		},
	})
	assert.Equal(t, &HeadersRequest{
		EnableGoogleCloudServerlessAuthentication: true,
		Issuer:     "from.example.com",
		Audience:   "from.example.com",
		ToAudience: "https://to.example.com",
		ClientCertificate: ClientCertificateInfo{
			Leaf: "--- FAKE CERTIFICATE ---",
		},
	}, req)
}

func TestNewHeadersRequestFromPolicy_IssuerFormat(t *testing.T) {
	policy := &config.Policy{
		EnableGoogleCloudServerlessAuthentication: true,
		From: "https://*.example.com",
		To: config.WeightedURLs{
			{
				URL: *mustParseURL("http://to.example.com"),
			},
		},
	}
	for _, tc := range []struct {
		format           string
		expectedIssuer   string
		expectedAudience string
		err              string
	}{
		{
			format:           "",
			expectedIssuer:   "from.example.com",
			expectedAudience: "from.example.com",
		},
		{
			format:           "hostOnly",
			expectedIssuer:   "from.example.com",
			expectedAudience: "from.example.com",
		},
		{
			format:           "uri",
			expectedIssuer:   "https://from.example.com/",
			expectedAudience: "from.example.com",
		},
		{
			format: "foo",
			err:    `invalid issuer format: "foo"`,
		},
	} {
		policy.JWTIssuerFormat = tc.format
		req, err := NewHeadersRequestFromPolicy(policy, RequestHTTP{
			Hostname: "from.example.com",
			ClientCertificate: ClientCertificateInfo{
				Leaf: "--- FAKE CERTIFICATE ---",
			},
		})
		if tc.err != "" {
			assert.ErrorContains(t, err, tc.err)
		} else {
			assert.Equal(t, &HeadersRequest{
				EnableGoogleCloudServerlessAuthentication: true,
				Issuer:     tc.expectedIssuer,
				Audience:   tc.expectedAudience,
				ToAudience: "https://to.example.com",
				ClientCertificate: ClientCertificateInfo{
					Leaf: "--- FAKE CERTIFICATE ---",
				},
			}, req)
		}
	}
}

func TestNewHeadersRequestFromPolicy_nil(t *testing.T) {
	req, _ := NewHeadersRequestFromPolicy(nil, RequestHTTP{Hostname: "from.example.com"})
	assert.Equal(t, &HeadersRequest{
		Issuer:   "from.example.com",
		Audience: "from.example.com",
	}, req)
}

func TestHeadersEvaluator(t *testing.T) {
	t.Parallel()

	type A = []any
	type M = map[string]any

	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(t, err)
	encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(t, err)
	privateJWK, err := cryptutil.PrivateJWKFromBytes(encodedSigningKey)
	require.NoError(t, err)
	publicJWK, err := cryptutil.PublicJWKFromBytes(encodedSigningKey)
	require.NoError(t, err)

	iat := time.Unix(1686870680, 0)

	eval := func(_ *testing.T, data []proto.Message, input *HeadersRequest) (*HeadersResponse, error) {
		ctx := context.Background()
		ctx = storage.WithQuerier(ctx, storage.NewStaticQuerier(data...))
		store := store.New()
		store.UpdateJWTClaimHeaders(config.NewJWTClaimHeaders("name", "email", "groups", "user", "CUSTOM_KEY"))
		store.UpdateSigningKey(privateJWK)
		e := NewHeadersEvaluator(store)
		return e.Evaluate(ctx, input, rego.EvalTime(iat))
	}

	t.Run("jwt", func(t *testing.T) {
		output, err := eval(t,
			[]proto.Message{
				&session.Session{Id: "s1", ImpersonateSessionId: proto.String("s2"), UserId: "u1"},
				&session.Session{Id: "s2", UserId: "u2", Claims: map[string]*structpb.ListValue{
					"name": {Values: []*structpb.Value{
						structpb.NewStringValue("n1"),
					}},
					"CUSTOM_KEY": {Values: []*structpb.Value{
						structpb.NewStringValue("v1"),
						structpb.NewStringValue("v2"),
						structpb.NewStringValue("v3"),
					}},
				}, IssuedAt: timestamppb.New(iat)},
				&user.User{Id: "u2", Claims: map[string]*structpb.ListValue{
					"name": {Values: []*structpb.Value{
						structpb.NewStringValue("n1"),
					}},
				}},
				newDirectoryUserRecord(directory.User{ID: "u2", GroupIDs: []string{"g1", "g2", "g3", "g4"}}),
				newDirectoryGroupRecord(directory.Group{ID: "g1", Name: "GROUP1", Email: "g1@example.com"}),
				newDirectoryGroupRecord(directory.Group{ID: "g2", Name: "GROUP2", Email: "g2@example.com"}),
				newDirectoryGroupRecord(directory.Group{ID: "g3", Name: "GROUP3", Email: "g3@example.com"}),
				newDirectoryGroupRecord(directory.Group{ID: "g4", Name: "GROUP4", Email: "g4@example.com"}),
			},
			&HeadersRequest{
				Issuer:     "from.example.com",
				Audience:   "from.example.com",
				ToAudience: "to.example.com",
				Session: RequestSession{
					ID: "s1",
				},
			})
		require.NoError(t, err)

		jwtHeader := output.Headers.Get("X-Pomerium-Jwt-Assertion")

		// Make sure the 'iat' and 'exp' claims can be parsed as an integer. We
		// need to do some explicit decoding in order to be able to verify
		// this, as by default json.Unmarshal() will make no distinction
		// between numeric formats.
		d := json.NewDecoder(bytes.NewReader(decodeJWSPayload(t, jwtHeader)))
		d.UseNumber()
		var jwtPayloadDecoded map[string]any
		err = d.Decode(&jwtPayloadDecoded)
		require.NoError(t, err)

		// The 'iat' and 'exp' claims are set based on the current time.
		assert.Equal(t, json.Number(fmt.Sprint(iat.Unix())), jwtPayloadDecoded["iat"],
			"unexpected 'iat' timestamp format")
		assert.Equal(t, json.Number(fmt.Sprint(iat.Add(5*time.Minute).Unix())), jwtPayloadDecoded["exp"],
			"unexpected 'exp' timestamp format")

		rawJWT, err := jwt.ParseSigned(jwtHeader)
		require.NoError(t, err)

		var claims M
		err = rawJWT.Claims(publicJWK, &claims)
		require.NoError(t, err)

		assert.NotEmpty(t, claims["jti"])
		assert.Equal(t, claims["iss"], "from.example.com")
		assert.Equal(t, claims["aud"], "from.example.com")
		assert.Equal(t, claims["exp"], math.Round(claims["exp"].(float64)))
		assert.LessOrEqual(t, claims["exp"], float64(time.Now().Add(time.Minute*6).Unix()),
			"JWT should expire within 5 minutes, but got: %v", claims["exp"])
		assert.Equal(t, "s1", claims["sid"], "should set session id to input session id")
		assert.Equal(t, "u2", claims["sub"], "should set subject to user id")
		assert.Equal(t, "u2", claims["user"], "should set user to user id")
		assert.Equal(t, "n1", claims["name"], "should set name")
		assert.Equal(t, "v1,v2,v3", claims["CUSTOM_KEY"], "should set CUSTOM_KEY")
		assert.Equal(t, []any{"g1", "g2", "g3", "g4", "GROUP1", "GROUP2", "GROUP3", "GROUP4"}, claims["groups"])
	})

	t.Run("jwt no groups", func(t *testing.T) {
		t.Parallel()

		output, err := eval(t,
			[]protoreflect.ProtoMessage{
				&session.Session{Id: "s1", UserId: "u1", Claims: map[string]*structpb.ListValue{
					"name": {Values: []*structpb.Value{
						structpb.NewStringValue("User Name"),
					}},
				}},
			},
			&HeadersRequest{
				Session: RequestSession{ID: "s1"},
			})
		require.NoError(t, err)
		jwtHeader := output.Headers.Get("X-Pomerium-Jwt-Assertion")
		var decoded map[string]any
		err = json.Unmarshal(decodeJWSPayload(t, jwtHeader), &decoded)
		require.NoError(t, err)
		assert.Equal(t, []any{}, decoded["groups"])
	})

	t.Run("set_request_headers", func(t *testing.T) {
		output, err := eval(t,
			[]proto.Message{
				&session.Session{Id: "s1", IdToken: &session.IDToken{
					Raw: "ID_TOKEN",
				}, OauthToken: &session.OAuthToken{
					AccessToken: "ACCESS_TOKEN",
				}},
			},
			&HeadersRequest{
				Issuer:     "from.example.com",
				Audience:   "from.example.com",
				ToAudience: "to.example.com",
				Session:    RequestSession{ID: "s1"},
				SetRequestHeaders: map[string]string{
					"X-Custom-Header":         "CUSTOM_VALUE",
					"X-ID-Token":              "${pomerium.id_token}",
					"X-Access-Token":          "${pomerium.access_token}",
					"Client-Cert-Fingerprint": "${pomerium.client_cert_fingerprint}",
					"Authorization":           "Bearer ${pomerium.jwt}",
					"Foo":                     "escaped $$dollar sign",
				},
				ClientCertificate: ClientCertificateInfo{Leaf: testValidCert},
			})
		require.NoError(t, err)

		assert.Equal(t, "CUSTOM_VALUE", output.Headers.Get("X-Custom-Header"))
		assert.Equal(t, "ID_TOKEN", output.Headers.Get("X-ID-Token"))
		assert.Equal(t, "ACCESS_TOKEN", output.Headers.Get("X-Access-Token"))
		assert.Equal(t, "3febe6467787e93f0a01030e0803072feaa710f724a9dc74de05cfba3d4a6d23",
			output.Headers.Get("Client-Cert-Fingerprint"))
		assert.Equal(t, "escaped $dollar sign", output.Headers.Get("Foo"))
		authHeader := output.Headers.Get("Authorization")
		assert.True(t, strings.HasPrefix(authHeader, "Bearer "))
		authHeader = strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.ParseSigned(authHeader)
		require.NoError(t, err)
		var claims jwt.Claims
		require.NoError(t, token.Claims(publicJWK, &claims))
		assert.Equal(t, "from.example.com", claims.Issuer)
		assert.Equal(t, jwt.Audience{"from.example.com"}, claims.Audience)
	})

	t.Run("set_request_headers no repeated substitution", func(t *testing.T) {
		output, err := eval(t,
			[]proto.Message{
				&session.Session{Id: "s1", IdToken: &session.IDToken{
					Raw: "$pomerium.access_token",
				}, OauthToken: &session.OAuthToken{
					AccessToken: "ACCESS_TOKEN",
				}},
			},
			&HeadersRequest{
				Issuer:     "from.example.com",
				Audience:   "from.example.com",
				ToAudience: "to.example.com",
				Session:    RequestSession{ID: "s1"},
				SetRequestHeaders: map[string]string{
					"X-ID-Token": "${pomerium.id_token}",
				},
			})
		require.NoError(t, err)

		assert.Equal(t, "$pomerium.access_token", output.Headers.Get("X-ID-Token"))
	})

	t.Run("set_request_headers original behavior", func(t *testing.T) {
		output, err := eval(t,
			[]proto.Message{
				&session.Session{Id: "s1", IdToken: &session.IDToken{
					Raw: "ID_TOKEN",
				}, OauthToken: &session.OAuthToken{
					AccessToken: "ACCESS_TOKEN",
				}},
			},
			&HeadersRequest{
				Issuer:     "from.example.com",
				Audience:   "from.example.com",
				ToAudience: "to.example.com",
				Session:    RequestSession{ID: "s1"},
				SetRequestHeaders: map[string]string{
					"Authorization": "Bearer ${pomerium.id_token}",
				},
			})
		require.NoError(t, err)

		assert.Equal(t, "Bearer ID_TOKEN", output.Headers.Get("Authorization"))
	})

	t.Run("set_request_headers no client cert", func(t *testing.T) {
		output, err := eval(t, nil,
			&HeadersRequest{
				Issuer:     "from.example.com",
				Audience:   "from.example.com",
				ToAudience: "to.example.com",
				SetRequestHeaders: map[string]string{
					"fingerprint": "${pomerium.client_cert_fingerprint}",
				},
			})
		require.NoError(t, err)

		assert.Equal(t, "", output.Headers.Get("fingerprint"))
	})

	t.Run("kubernetes", func(t *testing.T) {
		t.Parallel()

		output, err := eval(t,
			[]protoreflect.ProtoMessage{
				&session.Session{Id: "s1", UserId: "u1"},
				&user.User{Id: "u1", Email: "u1@example.com"},
				newDirectoryUserRecord(directory.User{
					ID:       "u1",
					GroupIDs: []string{"g1", "g2", "g3"},
				}),
				newDirectoryGroupRecord(directory.Group{
					ID:   "g1",
					Name: "GROUP1",
				}),
				newDirectoryGroupRecord(directory.Group{
					ID:   "g2",
					Name: "GROUP2",
				}),
			},
			&HeadersRequest{
				Issuer:                        "from.example.com",
				Audience:                      "from.example.com",
				ToAudience:                    "to.example.com",
				KubernetesServiceAccountToken: "TOKEN",
				Session:                       RequestSession{ID: "s1"},
			})
		require.NoError(t, err)
		assert.Equal(t, "Bearer TOKEN", output.Headers.Get("Authorization"))
		assert.Equal(t, "u1@example.com", output.Headers.Get("Impersonate-User"))
		assert.Equal(t, "g1,g2,g3,GROUP1,GROUP2", output.Headers.Get("Impersonate-Group"))
	})

	t.Run("routing key", func(t *testing.T) {
		t.Parallel()

		output, err := eval(t,
			[]protoreflect.ProtoMessage{},
			&HeadersRequest{
				EnableRoutingKey: false,
				Session:          RequestSession{ID: "s1"},
			})
		require.NoError(t, err)
		assert.Empty(t, output.Headers.Get("X-Pomerium-Routing-Key"))

		output, err = eval(t,
			[]protoreflect.ProtoMessage{},
			&HeadersRequest{
				EnableRoutingKey: true,
				Session:          RequestSession{ID: "s1"},
			})
		require.NoError(t, err)
		assert.Equal(t, "e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc", output.Headers.Get("X-Pomerium-Routing-Key"))
	})

	t.Run("jwt payload email", func(t *testing.T) {
		t.Parallel()

		output, err := eval(t,
			[]protoreflect.ProtoMessage{
				&session.Session{Id: "s1", UserId: "u1"},
				&user.User{Id: "u1", Email: "user@example.com"},
			},
			&HeadersRequest{
				Session: RequestSession{ID: "s1"},
			})
		require.NoError(t, err)
		assert.Equal(t, "user@example.com", output.Headers.Get("X-Pomerium-Claim-Email"))

		output, err = eval(t,
			[]protoreflect.ProtoMessage{
				&session.Session{Id: "s1", UserId: "u1"},
				newDirectoryUserRecord(directory.User{ID: "u1", Email: "directory-user@example.com"}),
			},
			&HeadersRequest{
				Session: RequestSession{ID: "s1"},
			})
		require.NoError(t, err)
		assert.Equal(t, "directory-user@example.com", output.Headers.Get("X-Pomerium-Claim-Email"))
	})
	t.Run("jwt payload name", func(t *testing.T) {
		t.Parallel()

		output, err := eval(t,
			[]protoreflect.ProtoMessage{
				&session.Session{Id: "s1", UserId: "u1", Claims: map[string]*structpb.ListValue{
					"name": {Values: []*structpb.Value{
						structpb.NewStringValue("NAME_FROM_SESSION"),
					}},
				}},
			},
			&HeadersRequest{
				Session: RequestSession{ID: "s1"},
			})
		require.NoError(t, err)
		assert.Equal(t, "NAME_FROM_SESSION", output.Headers.Get("X-Pomerium-Claim-Name"))

		output, err = eval(t,
			[]protoreflect.ProtoMessage{
				&session.Session{Id: "s1", UserId: "u1"},
				&user.User{Id: "u1", Claims: map[string]*structpb.ListValue{
					"name": {Values: []*structpb.Value{
						structpb.NewStringValue("NAME_FROM_USER"),
					}},
				}},
			},
			&HeadersRequest{
				Session: RequestSession{ID: "s1"},
			})
		require.NoError(t, err)
		assert.Equal(t, "NAME_FROM_USER", output.Headers.Get("X-Pomerium-Claim-Name"))
	})

	t.Run("service account", func(t *testing.T) {
		t.Parallel()

		output, err := eval(t,
			[]protoreflect.ProtoMessage{
				&user.ServiceAccount{Id: "sa1", UserId: "u1"},
				&user.User{Id: "u1", Email: "u1@example.com"},
			},
			&HeadersRequest{
				Session: RequestSession{ID: "sa1"},
			})
		require.NoError(t, err)
		assert.Equal(t, "u1@example.com", output.Headers.Get("X-Pomerium-Claim-Email"))
	})
}

func decodeJWSPayload(t *testing.T, jws string) []byte {
	t.Helper()

	// A compact JWS string should consist of three base64-encoded values,
	// separated by a '.' character. The payload is the middle one of these.
	// cf. https://www.rfc-editor.org/rfc/rfc7515#section-7.1
	parts := strings.Split(jws, ".")
	require.Equal(t, 3, len(parts), "jws should have 3 parts: %s", jws)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	return payload
}

func newDirectoryGroupRecord(directoryGroup directory.Group) *databroker.Record {
	m := map[string]any{}
	bs, _ := json.Marshal(directoryGroup)
	_ = json.Unmarshal(bs, &m)
	s, _ := structpb.NewStruct(m)
	return storage.NewStaticRecord(directory.GroupRecordType, s)
}

func newDirectoryUserRecord(directoryUser directory.User) *databroker.Record {
	m := map[string]any{}
	bs, _ := json.Marshal(directoryUser)
	_ = json.Unmarshal(bs, &m)
	s, _ := structpb.NewStruct(m)
	return storage.NewStaticRecord(directory.UserRecordType, s)
}
