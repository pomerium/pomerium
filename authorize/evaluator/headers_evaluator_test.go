package evaluator

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/policy/input"
	"github.com/pomerium/pomerium/pkg/storage"
)

func BenchmarkHeadersEvaluator(b *testing.B) {
	ctx := context.Background()

	privateJWK, _ := newJWK(b)

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

	req := &Request{
		HTTP: input.RequestHTTP{
			Method:   "GET",
			Hostname: "from.example.com",
		},
		Policy: &config.Policy{
			SetRequestHeaders: map[string]string{
				"X-Custom-Header":         "CUSTOM_VALUE",
				"X-ID-Token":              "${pomerium.id_token}",
				"X-Access-Token":          "${pomerium.access_token}",
				"Client-Cert-Fingerprint": "${pomerium.client_cert_fingerprint}",
				"Authorization":           "Bearer ${pomerium.jwt}",
			},
		},
		Session: input.RequestSession{
			ID: "s1",
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := e.Evaluate(ctx, req, rego.EvalTime(iat))
		require.NoError(b, err)
		_ = res
	}
}

func TestHeadersEvaluator(t *testing.T) {
	t.Parallel()

	type A = []any
	type M = map[string]any

	privateJWK, publicJWK := newJWK(t)

	iat := time.Unix(1686870680, 0)

	eval := func(_ *testing.T, data []proto.Message, input *Request) (*HeadersResponse, error) {
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
			&Request{
				HTTP: input.RequestHTTP{
					Hostname: "from.example.com",
				},
				Policy: &config.Policy{},
				Session: input.RequestSession{
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
			&Request{
				Session: input.RequestSession{ID: "s1"},
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
			&Request{
				HTTP: input.RequestHTTP{
					Hostname:          "from.example.com",
					ClientCertificate: input.ClientCertificateInfo{Leaf: testValidCert},
					Headers: map[string]string{
						"X-Incoming-Header": "INCOMING",
					},
				},
				Policy: &config.Policy{
					SetRequestHeaders: map[string]string{
						"X-Custom-Header":          "CUSTOM_VALUE",
						"X-ID-Token":               "${pomerium.id_token}",
						"X-Access-Token":           "${pomerium.access_token}",
						"Client-Cert-Fingerprint":  "${pomerium.client_cert_fingerprint}",
						"Authorization":            "Bearer ${pomerium.jwt}",
						"Foo":                      "escaped $$dollar sign",
						"X-Incoming-Custom-Header": `From-Incoming ${pomerium.request.headers["X-Incoming-Header"]}`,
					},
				},
				Session: input.RequestSession{ID: "s1"},
			})
		require.NoError(t, err)

		assert.Equal(t, "CUSTOM_VALUE", output.Headers.Get("X-Custom-Header"))
		assert.Equal(t, "ID_TOKEN", output.Headers.Get("X-ID-Token"))
		assert.Equal(t, "ACCESS_TOKEN", output.Headers.Get("X-Access-Token"))
		assert.Equal(t, "3febe6467787e93f0a01030e0803072feaa710f724a9dc74de05cfba3d4a6d23",
			output.Headers.Get("Client-Cert-Fingerprint"))
		assert.Equal(t, "escaped $dollar sign", output.Headers.Get("Foo"))
		assert.Equal(t, "From-Incoming INCOMING", output.Headers.Get("X-Incoming-Custom-Header"))
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
			&Request{
				Session: input.RequestSession{ID: "s1"},
				Policy: &config.Policy{
					SetRequestHeaders: map[string]string{
						"X-ID-Token": "${pomerium.id_token}",
					},
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
			&Request{
				Policy: &config.Policy{
					SetRequestHeaders: map[string]string{
						"Authorization": "Bearer ${pomerium.id_token}",
					},
				},
				Session: input.RequestSession{ID: "s1"},
			})
		require.NoError(t, err)

		assert.Equal(t, "Bearer ID_TOKEN", output.Headers.Get("Authorization"))
	})

	t.Run("set_request_headers no client cert", func(t *testing.T) {
		output, err := eval(t, nil,
			&Request{
				Policy: &config.Policy{
					SetRequestHeaders: map[string]string{
						"fingerprint": "${pomerium.client_cert_fingerprint}",
					},
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
			&Request{
				Policy: &config.Policy{
					KubernetesServiceAccountToken: "TOKEN",
				},
				Session: input.RequestSession{ID: "s1"},
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
			&Request{
				Session: input.RequestSession{ID: "s1"},
			})
		require.NoError(t, err)
		assert.Empty(t, output.Headers.Get("X-Pomerium-Routing-Key"))

		output, err = eval(t,
			[]protoreflect.ProtoMessage{},
			&Request{
				Policy: &config.Policy{
					EnvoyOpts: &envoy_config_cluster_v3.Cluster{
						LbPolicy: envoy_config_cluster_v3.Cluster_MAGLEV,
					},
				},
				Session: input.RequestSession{ID: "s1"},
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
			&Request{
				Session: input.RequestSession{ID: "s1"},
			})
		require.NoError(t, err)
		assert.Equal(t, "user@example.com", output.Headers.Get("X-Pomerium-Claim-Email"))

		output, err = eval(t,
			[]protoreflect.ProtoMessage{
				&session.Session{Id: "s1", UserId: "u1"},
				newDirectoryUserRecord(directory.User{ID: "u1", Email: "directory-user@example.com"}),
			},
			&Request{
				Session: input.RequestSession{ID: "s1"},
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
			&Request{
				Session: input.RequestSession{ID: "s1"},
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
			&Request{
				Session: input.RequestSession{ID: "s1"},
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
			&Request{
				Session: input.RequestSession{ID: "sa1"},
			})
		require.NoError(t, err)
		assert.Equal(t, "u1@example.com", output.Headers.Get("X-Pomerium-Claim-Email"))
	})
}

func TestHeadersEvaluator_JWTIssuerFormat(t *testing.T) {
	privateJWK, _ := newJWK(t)

	store := store.New()
	store.UpdateSigningKey(privateJWK)

	eval := func(_ *testing.T, input *Request) (*HeadersResponse, error) {
		ctx := context.Background()
		e := NewHeadersEvaluator(store)
		return e.Evaluate(ctx, input)
	}

	hostname := "route.example.com"

	cases := []struct {
		globalFormat config.JWTIssuerFormat
		routeFormat  config.JWTIssuerFormat
		expected     string
	}{
		{"", "", "route.example.com"},
		{"hostOnly", "", "route.example.com"},
		{"uri", "", "https://route.example.com/"},

		{"", "hostOnly", "route.example.com"},
		{"hostOnly", "hostOnly", "route.example.com"},
		{"uri", "hostOnly", "route.example.com"},

		{"", "uri", "https://route.example.com/"},
		{"hostOnly", "uri", "https://route.example.com/"},
		{"uri", "uri", "https://route.example.com/"},
	}

	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			store.UpdateDefaultJWTIssuerFormat(tc.globalFormat)
			output, err := eval(t,
				&Request{
					HTTP: input.RequestHTTP{
						Hostname: hostname,
					},
					Policy: &config.Policy{
						JWTIssuerFormat: tc.routeFormat,
					},
				})
			require.NoError(t, err)
			m := decodeJWTAssertion(t, output.Headers)
			assert.Equal(t, tc.expected, m["iss"],
				"unexpected issuer for global format=%q, route format=%q",
				tc.globalFormat, tc.routeFormat)
		})
	}
}

func TestHeadersEvaluator_JWTGroupsFilter(t *testing.T) {
	t.Parallel()

	privateJWK, _ := newJWK(t)

	// Create some user and groups data.
	var records []proto.Message
	groupsCount := 50
	for i := 1; i <= groupsCount; i++ {
		id := fmt.Sprint(i)
		records = append(records, newDirectoryGroupRecord(directory.Group{ID: id, Name: "GROUP-" + id}))
	}
	for i := 1; i <= 10; i++ {
		id := fmt.Sprintf("USER-%d", i)
		// User 1 will be in every group, user 2 in every other group, user 3 in every third group, etc.
		var groups []string
		for j := i; j <= groupsCount; j += i {
			groups = append(groups, fmt.Sprint(j))
		}
		records = append(records,
			&session.Session{Id: fmt.Sprintf("SESSION-%d", i), UserId: id},
			newDirectoryUserRecord(directory.User{ID: id, GroupIDs: groups}),
		)
	}
	// Also add a user session with an upstream "groups" claim from the IdP.
	records = append(records,
		&session.Session{Id: "SESSION-11", UserId: "USER-11", Claims: map[string]*structpb.ListValue{
			"groups": newList("foo", "bar", "baz"),
		}},
	)

	cases := []struct {
		name         string
		globalFilter []string
		routeFilter  []string
		sessionID    string
		expected     []any
		removed      int
	}{
		{"global filter 1", []string{"42", "1"}, nil, "SESSION-1", []any{"1", "42", "GROUP-1", "GROUP-42"}, 48},
		{"global filter 2", []string{"42", "1"}, nil, "SESSION-2", []any{"42", "GROUP-42"}, 24},
		{"route filter 1", nil, []string{"42", "1"}, "SESSION-1", []any{"1", "42", "GROUP-1", "GROUP-42"}, 48},
		{"route filter 2", nil, []string{"42", "1"}, "SESSION-2", []any{"42", "GROUP-42"}, 24},
		{"both filters 1", []string{"1"}, []string{"42"}, "SESSION-1", []any{"1", "42", "GROUP-1", "GROUP-42"}, 48},
		{"both filters 2", []string{"1"}, []string{"42"}, "SESSION-2", []any{"42", "GROUP-42"}, 24},
		{"cannot filter by name", []string{"GROUP-1"}, nil, "SESSION-1", []any{}, 50},
		{"overlapping", []string{"1"}, []string{"1"}, "SESSION-1", []any{"1", "GROUP-1"}, 49},
		{"empty route filter", []string{"1", "2", "3"}, []string{}, "SESSION-1", []any{"1", "2", "3", "GROUP-1", "GROUP-2", "GROUP-3"}, 47},
		{
			"no filtering", nil, nil, "SESSION-10",
			[]any{"10", "20", "30", "40", "50", "GROUP-10", "GROUP-20", "GROUP-30", "GROUP-40", "GROUP-50"},
			0,
		},
		// filtering has no effect on groups from an IdP "groups" claim
		{"groups claim", []string{"foo", "quux"}, nil, "SESSION-11", []any{"foo", "bar", "baz"}, 0},
	}

	ctx := storage.WithQuerier(context.Background(), storage.NewStaticQuerier(records...))
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := store.New()
			store.UpdateSigningKey(privateJWK)
			store.UpdateJWTGroupsFilter(config.NewJWTGroupsFilter(c.globalFilter))
			req := &Request{Session: input.RequestSession{ID: c.sessionID}}
			if c.routeFilter != nil {
				req.Policy = &config.Policy{
					JWTGroupsFilter: config.NewJWTGroupsFilter(c.routeFilter),
				}
			}
			e := NewHeadersEvaluator(store)
			resp, err := e.Evaluate(ctx, req)
			require.NoError(t, err)
			decoded := decodeJWTAssertion(t, resp.Headers)
			assert.Equal(t, c.expected, decoded["groups"])
			if c.removed > 0 {
				assert.Equal(t, c.removed, resp.AdditionalLogFields[log.AuthorizeLogFieldRemovedGroupsCount])
			} else {
				assert.Nil(t, resp.AdditionalLogFields[log.AuthorizeLogFieldRemovedGroupsCount])
			}
		})
	}
}

func newJWK(t testing.TB) (privateJWK, publicJWK *jose.JSONWebKey) {
	t.Helper()
	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(t, err)
	encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(t, err)
	privateJWK, err = cryptutil.PrivateJWKFromBytes(encodedSigningKey)
	require.NoError(t, err)
	publicJWK, err = cryptutil.PublicJWKFromBytes(encodedSigningKey)
	require.NoError(t, err)
	return
}

func decodeJWTAssertion(t *testing.T, headers http.Header) map[string]any {
	jwtHeader := headers.Get("X-Pomerium-Jwt-Assertion")
	// Make sure the 'iat' and 'exp' claims can be parsed as an integer. We
	// need to do some explicit decoding in order to be able to verify
	// this, as by default json.Unmarshal() will make no distinction
	// between numeric formats.
	d := json.NewDecoder(bytes.NewReader(decodeJWSPayload(t, jwtHeader)))
	d.UseNumber()
	var m map[string]any
	err := d.Decode(&m)
	require.NoError(t, err)
	return m
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

func newList(v ...any) *structpb.ListValue {
	lv, _ := structpb.NewList(v)
	return lv
}
