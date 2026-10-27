package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// failingClientStorage makes GetClient fail with a given error, standing in for
// a databroker that is unreachable rather than one that has no such client.
type failingClientStorage struct {
	HandlerStorage
	err error
}

func (s *failingClientStorage) GetClient(context.Context, string) (*rfc7591v1.ClientRegistration, error) {
	return nil, s.err
}

// TestTokenClientLookupFailureIsNotClientError checks that Pomerium being unable
// to look a client up is reported as a server fault, not as invalid_client.
//
// invalid_client is what tells a client its registration is dead and it must
// register again. Reporting it for a transient databroker outage would push
// every client in the fleet into re-registration and interactive re-consent
// over a blip, which is a worse failure than the invalid_request it replaced.
func TestTokenClientLookupFailureIsNotClientError(t *testing.T) {
	ctx := context.Background()
	base := setupTestDatabroker(ctx, t)

	testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
	require.NoError(t, err)

	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
		wantError  string
	}{
		{
			name:       "databroker unavailable",
			err:        status.Error(codes.Unavailable, "connection refused"),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "databroker deadline exceeded",
			err:        status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "client metadata fetch failed",
			err:        fmt.Errorf("%w: upstream returned 502", ErrClientMetadataFetch),
			wantStatus: http.StatusInternalServerError,
		},
		{
			// The contrast case: the client really is gone.
			name:       "client not found",
			err:        status.Error(codes.NotFound, "record not found"),
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_client",
		},
		{
			// A malformed metadata document is the client's fault.
			name:       "client metadata invalid",
			err:        fmt.Errorf("%w: client_id mismatch", ErrClientMetadataValidation),
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_client",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &Handler{
				cipher:  testCipher,
				storage: &failingClientStorage{HandlerStorage: base, err: tc.err},
			}

			form := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"stale-refresh-token"},
				"client_id":     {"c0ffee00-0000-4000-8000-000000000000"},
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/token", strings.NewReader(form.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			w := httptest.NewRecorder()
			srv.Token(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)
			if tc.wantError != "" {
				var body map[string]any
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
				assert.Equal(t, tc.wantError, body["error"])
			} else {
				assert.NotContains(t, w.Body.String(), "invalid_client",
					"a server-side failure must not tell the client its registration is dead")
			}
		})
	}
}

// TestTokenClientAuthenticationErrors covers the OAuth 2.1 3.2.3.1 requirement
// that client authentication failures at the token endpoint are reported as
// invalid_client, not invalid_request.
//
// This matters beyond pedantry: MCP clients persist dynamic client registrations
// and only re-register when the authorization server tells them their client is
// no longer valid. Reporting invalid_request instead leaves a client that holds a
// registration the databroker no longer has (for example after the storage was
// cleared) stuck retrying a client_id that will never work again.
func TestTokenClientAuthenticationErrors(t *testing.T) {
	ctx := context.Background()
	storage := setupTestDatabroker(ctx, t)

	testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
	require.NoError(t, err)
	srv := &Handler{cipher: testCipher, storage: storage}

	const unregisteredClientID = "a5c6ef34-0c3e-4a0e-9a03-1f8d0a5b0c11"

	for _, tc := range []struct {
		name string
		// authMethod and secret describe the client to register first. An empty
		// authMethod means the case registers no client at all.
		authMethod string
		secret     *rfc7591v1.ClientSecret
		// form is merged over the default refresh_token grant. A registered
		// client's id is substituted for the "client_id" placeholder below.
		form url.Values
		// basicSecret, when non-nil, is sent with the client id as HTTP Basic
		// credentials. basicUser overrides the username, which defaults to the
		// registered client id.
		basicSecret *string
		basicUser   *string
		// rawAuthHeader, when set, is sent verbatim as the Authorization header.
		rawAuthHeader string
		// query is appended to the request URL. Credentials in the query string
		// are not a valid transport and must never authenticate a client.
		query url.Values
		// omitClientID drops client_id from the form, e.g. when it travels in
		// the Authorization header instead.
		omitClientID bool

		wantStatus    int
		wantError     string
		wantChallenge string
	}{
		{
			// The reproduction case: a client presents a client_id for a
			// registration the databroker no longer holds.
			name:       "unknown client id",
			form:       url.Values{"client_id": {unregisteredClientID}},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_client",
		},
		{
			name:       "client_secret_post with wrong secret",
			authMethod: rfc7591v1.TokenEndpointAuthMethodClientSecretPost,
			secret:     &rfc7591v1.ClientSecret{Value: "correct-secret"},
			form:       url.Values{"client_secret": {"wrong-secret"}},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_client",
		},
		{
			name:       "client_secret_post with no secret",
			authMethod: rfc7591v1.TokenEndpointAuthMethodClientSecretPost,
			secret:     &rfc7591v1.ClientSecret{Value: "correct-secret"},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_client",
		},
		{
			name:       "expired client secret",
			authMethod: rfc7591v1.TokenEndpointAuthMethodClientSecretPost,
			secret: &rfc7591v1.ClientSecret{
				Value:     "correct-secret",
				ExpiresAt: timestamppb.New(time.Now().Add(-time.Hour)),
			},
			form:       url.Values{"client_secret": {"correct-secret"}},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_client",
		},
		{
			// OAuth 2.1 3.2.4 requires a 401 with WWW-Authenticate when the
			// client tried to authenticate via the Authorization header.
			name:          "unknown client id over basic auth",
			basicSecret:   new("any-secret"),
			omitClientID:  true,
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_client",
			wantChallenge: `Basic realm="pomerium"`,
		},
		{
			name:          "client_secret_basic with wrong secret",
			authMethod:    rfc7591v1.TokenEndpointAuthMethodClientSecretBasic,
			secret:        &rfc7591v1.ClientSecret{Value: "correct-secret"},
			basicSecret:   new("wrong-secret"),
			omitClientID:  true,
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_client",
			wantChallenge: `Basic realm="pomerium"`,
		},
		{
			name:       "client_secret_basic with no credentials",
			authMethod: rfc7591v1.TokenEndpointAuthMethodClientSecretBasic,
			secret:     &rfc7591v1.ClientSecret{Value: "correct-secret"},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_client",
		},
		{
			// OAuth 2.1 2.3 ties a client to the method it registered for. The
			// secret alone is not enough: it has to arrive the registered way.
			name:       "client_secret_basic rejects a body secret",
			authMethod: rfc7591v1.TokenEndpointAuthMethodClientSecretBasic,
			secret:     &rfc7591v1.ClientSecret{Value: "correct-secret"},
			form:       url.Values{"client_secret": {"correct-secret"}},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_client",
		},
		{
			name:          "client_secret_post rejects a basic header",
			authMethod:    rfc7591v1.TokenEndpointAuthMethodClientSecretPost,
			secret:        &rfc7591v1.ClientSecret{Value: "correct-secret"},
			basicSecret:   new("correct-secret"),
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_client",
			wantChallenge: `Basic realm="pomerium"`,
		},
		{
			// ParseTokenRequest reads client_secret with the query-aware
			// FormValue, so a query parameter must not stand in for the Basic
			// password the client is registered to prove.
			name:          "client_secret_basic rejects a query secret",
			authMethod:    rfc7591v1.TokenEndpointAuthMethodClientSecretBasic,
			secret:        &rfc7591v1.ClientSecret{Value: "correct-secret"},
			basicSecret:   new("wrong-secret"),
			omitClientID:  true,
			query:         url.Values{"client_secret": {"correct-secret"}},
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_client",
			wantChallenge: `Basic realm="pomerium"`,
		},
		{
			name:       "client_secret_post rejects a query secret",
			authMethod: rfc7591v1.TokenEndpointAuthMethodClientSecretPost,
			secret:     &rfc7591v1.ClientSecret{Value: "correct-secret"},
			query:      url.Values{"client_secret": {"correct-secret"}},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_client",
		},
		{
			// The Basic header names the client it authenticates, so a header
			// for one client must not authenticate a request naming another.
			name:          "basic credentials for a different client",
			authMethod:    rfc7591v1.TokenEndpointAuthMethodClientSecretBasic,
			secret:        &rfc7591v1.ClientSecret{Value: "correct-secret"},
			basicUser:     new("11111111-2222-4333-8444-555555555555"),
			basicSecret:   new("correct-secret"),
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_client",
			wantChallenge: `Basic realm="pomerium"`,
		},
		{
			// OAuth 2.1 2.4: a client must not use more than one authentication
			// mechanism, which is a malformed request rather than a bad client.
			name:        "both authentication mechanisms at once",
			authMethod:  rfc7591v1.TokenEndpointAuthMethodClientSecretBasic,
			secret:      &rfc7591v1.ClientSecret{Value: "correct-secret"},
			form:        url.Values{"client_secret": {"correct-secret"}},
			basicSecret: new("correct-secret"),
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid_request",
		},
		{
			// A Basic header Go cannot parse is still an attempt to authenticate
			// through the Authorization header, so it gets a challenge too.
			name:          "unknown client id with malformed basic header",
			rawAuthHeader: "Basic !!!not-base64",
			omitClientID:  true,
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_client",
			wantChallenge: `Basic realm="pomerium"`,
		},
		{
			// Guard against over-correcting: a malformed request, which never
			// reaches client authentication, is still invalid_request.
			name:         "malformed request stays invalid_request",
			form:         url.Values{"grant_type": nil},
			omitClientID: true,
			wantStatus:   http.StatusBadRequest,
			wantError:    "invalid_request",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientID := unregisteredClientID
			if tc.authMethod != "" {
				var err error
				clientID, err = storage.RegisterClient(ctx, &rfc7591v1.ClientRegistration{
					ResponseMetadata: &rfc7591v1.Metadata{
						TokenEndpointAuthMethod: new(tc.authMethod),
					},
					ClientSecret: tc.secret,
				})
				require.NoError(t, err)
			}

			form := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"stale-refresh-token"},
			}
			if !tc.omitClientID {
				form.Set("client_id", clientID)
			}
			for k, v := range tc.form {
				if v == nil {
					form.Del(k)
					continue
				}
				form[k] = v
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/token", strings.NewReader(form.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.query != nil {
				req.URL.RawQuery = tc.query.Encode()
			}
			switch {
			case tc.rawAuthHeader != "":
				req.Header.Set("Authorization", tc.rawAuthHeader)
			case tc.basicSecret != nil:
				user := clientID
				if tc.basicUser != nil {
					user = *tc.basicUser
				}
				req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
					[]byte(user+":"+*tc.basicSecret)))
			}

			w := httptest.NewRecorder()
			srv.Token(w, req)

			var body map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))

			assert.Equal(t, tc.wantStatus, w.Code)
			assert.Equal(t, tc.wantError, body["error"])
			assert.Equal(t, tc.wantChallenge, w.Header().Get("WWW-Authenticate"))

			// Every client-auth failure describes itself identically, so the
			// response cannot be used to probe which client_ids exist.
			if tc.wantError == "invalid_client" {
				assert.Equal(t,
					"client authentication failed: the client is unknown, or its credentials were rejected",
					body["error_description"])
			}
		})
	}
}
