package evaluator

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestNewHeadersRequestFromPolicy(t *testing.T) {
	req := NewHeadersRequestFromPolicy(&config.Policy{
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
		ToAudience: "https://to.example.com",
		ClientCertificate: ClientCertificateInfo{
			Leaf: "--- FAKE CERTIFICATE ---",
		},
	}, req)
}

func TestNewHeadersRequestFromPolicy_nil(t *testing.T) {
	req := NewHeadersRequestFromPolicy(nil, RequestHTTP{Hostname: "from.example.com"})
	assert.Equal(t, &HeadersRequest{
		Issuer: "from.example.com",
	}, req)
}

func TestHeadersEvaluator(t *testing.T) {
	t.Parallel()

	type A = []interface{}
	type M = map[string]interface{}

	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(t, err)
	encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(t, err)
	privateJWK, err := cryptutil.PrivateJWKFromBytes(encodedSigningKey)
	require.NoError(t, err)
	publicJWK, err := cryptutil.PublicJWKFromBytes(encodedSigningKey)
	require.NoError(t, err)

	eval := func(t *testing.T, data []proto.Message, input *HeadersRequest) (*HeadersResponse, error) {
		ctx := context.Background()
		ctx = storage.WithQuerier(ctx, storage.NewStaticQuerier(data...))
		store := store.New()
		store.UpdateJWTClaimHeaders(config.NewJWTClaimHeaders("email", "groups", "user", "CUSTOM_KEY"))
		store.UpdateSigningKey(privateJWK)
		e, err := NewHeadersEvaluator(ctx, store)
		require.NoError(t, err)
		return e.Evaluate(ctx, input)
	}

	iat := time.Unix(1686870680, 0)

	t.Run("jwt", func(t *testing.T) {
		output, err := eval(t,
			[]proto.Message{
				&session.Session{Id: "s1", ImpersonateSessionId: proto.String("s2"), UserId: "u1"},
				&session.Session{Id: "s2", UserId: "u2", Claims: map[string]*structpb.ListValue{
					"name": {Values: []*structpb.Value{
						structpb.NewStringValue("n1"),
					}},
				}, IssuedAt: timestamppb.New(iat)},
			},
			&HeadersRequest{
				Issuer:     "from.example.com",
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
		var jwtPayloadDecoded map[string]interface{}
		err = d.Decode(&jwtPayloadDecoded)
		require.NoError(t, err)

		// The 'iat' claim is set from the session store.
		assert.Equal(t, json.Number("1686870680"), jwtPayloadDecoded["iat"],
			"unexpected 'iat' timestamp format")

		// The 'exp' claim will vary with the current time, but we can still
		// use Atoi() to verify that it can be parsed as an integer.
		exp := string(jwtPayloadDecoded["exp"].(json.Number))
		_, err = strconv.Atoi(exp)
		assert.NoError(t, err, "unexpected 'exp' timestamp format")

		rawJWT, err := jwt.ParseSigned(jwtHeader)
		require.NoError(t, err)

		var claims M
		err = rawJWT.Claims(publicJWK, &claims)
		require.NoError(t, err)

		assert.Equal(t, claims["iss"], "from.example.com")
		assert.Equal(t, claims["aud"], "from.example.com")
		assert.Equal(t, claims["exp"], math.Round(claims["exp"].(float64)))
		assert.LessOrEqual(t, claims["exp"], float64(time.Now().Add(time.Minute*6).Unix()),
			"JWT should expire within 5 minutes, but got: %v", claims["exp"])
		assert.Equal(t, "s1", claims["sid"], "should set session id to input session id")
		assert.Equal(t, "u2", claims["sub"], "should set subject to user id")
		assert.Equal(t, "u2", claims["user"], "should set user to user id")
		assert.Equal(t, "n1", claims["name"], "should set name")
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
				ToAudience: "to.example.com",
				Session:    RequestSession{ID: "s1"},
				SetRequestHeaders: map[string]string{
					"X-Custom-Header":         "CUSTOM_VALUE",
					"X-ID-Token":              "${pomerium.id_token}",
					"X-Access-Token":          "${pomerium.access_token}",
					"Client-Cert-Fingerprint": "${pomerium.client_cert_fingerprint}",
					"Foo":                     "escaped $$dollar sign",
				},
				ClientCertificate: ClientCertificateInfo{Leaf: testValidCert},
			})
		require.NoError(t, err)

		assert.Equal(t, "CUSTOM_VALUE", output.Headers.Get("X-Custom-Header"))
		assert.Equal(t, "ID_TOKEN", output.Headers.Get("X-ID-Token"))
		assert.Equal(t, "ACCESS_TOKEN", output.Headers.Get("X-Access-Token"))
		assert.Equal(t, "ebf421e323e31c3900a7985a16e72c59f45f5a2c15283297567e226b3b17d1a1",
			output.Headers.Get("Client-Cert-Fingerprint"))
		assert.Equal(t, "escaped $dollar sign", output.Headers.Get("Foo"))
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
			},
			&HeadersRequest{
				Issuer:                        "from.example.com",
				ToAudience:                    "to.example.com",
				KubernetesServiceAccountToken: "TOKEN",
				Session:                       RequestSession{ID: "s1"},
			})
		require.NoError(t, err)
		assert.Equal(t, "Bearer TOKEN", output.Headers.Get("Authorization"))
		assert.Equal(t, "u1@example.com", output.Headers.Get("Impersonate-User"))
		assert.Empty(t, output.Headers["Impersonate-Group"])
	})
}

func decodeJWSPayload(t *testing.T, jws string) []byte {
	t.Helper()

	// A compact JWS string should consist of three base64-encoded values,
	// separated by a '.' character. The payload is the middle one of these.
	// cf. https://www.rfc-editor.org/rfc/rfc7515#section-7.1
	parts := strings.Split(jws, ".")
	require.Equal(t, 3, len(parts))
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	return payload
}
