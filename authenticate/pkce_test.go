package authenticate

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/pkce"
)

func newTestPKCEStore(t testing.TB) *pkceStore {
	t.Helper()
	opts := newTestOptions(&testing.T{}) // config only, no actual test state needed
	cookieSecret, err := opts.GetCookieSecret()
	require.NoError(t, err)
	aead, err := cryptutil.NewAEADCipher(cookieSecret)
	require.NoError(t, err)

	now := time.Unix(1000, 0)
	store := newPKCEStore(opts, aead, cookieSecret)
	store.now = func() time.Time { return now }
	return store
}

func TestPKCEStore_InitAndPop(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		initState   string // state used for InitVerifier ("" means skip init)
		popState    string // state used for PopVerifier
		advanceTime time.Duration
		tamper      bool
		wantErr     error // nil means success; sentinel or non-nil
		wantErrIs   bool  // use errors.Is check (for sentinel)
	}{
		{
			name:      "round_trip",
			initState: "state-a",
			popState:  "state-a",
		},
		{
			name:      "wrong_state",
			initState: "state-a",
			popState:  "state-b",
			wantErr:   errPKCEVerifierExpired,
			wantErrIs: true,
		},
		{
			name:        "expired",
			initState:   "state-a",
			popState:    "state-a",
			advanceTime: 10 * time.Minute,
			wantErr:     errPKCEVerifierExpired,
			wantErrIs:   true,
		},
		{
			name:      "tampered_cookie",
			initState: "state-a",
			popState:  "state-a",
			tamper:    true,
			wantErr:   errors.New("any"), // non-nil, but not the sentinel
		},
		{
			name:      "no_cookie",
			initState: "",
			popState:  "state-a",
			wantErr:   errPKCEVerifierExpired,
			wantErrIs: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newTestPKCEStore(t)

			var initVerifier string
			req := httptest.NewRequest(http.MethodGet, "https://auth.example/oauth2/callback", nil)

			if tc.initState != "" {
				rec := httptest.NewRecorder()
				initCtx, err := store.InitVerifier(context.Background(), rec, tc.initState)
				require.NoError(t, err)

				params, ok := pkce.FromContext(initCtx)
				require.True(t, ok, "InitVerifier must set PKCE context")
				assert.Equal(t, "S256", params.Method)
				assert.NotEmpty(t, params.Verifier)
				initVerifier = params.Verifier

				for _, c := range rec.Result().Cookies() {
					if tc.tamper {
						c.Value = "dGFtcGVyZWQ" // base64url("tampered")
					}
					req.AddCookie(c)
				}
			}

			if tc.advanceTime > 0 {
				advanced := store.now().Add(tc.advanceTime)
				store.now = func() time.Time { return advanced }
			}

			rec := httptest.NewRecorder()
			popCtx, err := store.PopVerifier(context.Background(), rec, req, tc.popState)

			if tc.wantErr != nil {
				require.Error(t, err)
				if tc.wantErrIs {
					assert.ErrorIs(t, err, tc.wantErr)
				}
				return
			}

			require.NoError(t, err)
			params, ok := pkce.FromContext(popCtx)
			require.True(t, ok, "PopVerifier must set PKCE context on success")
			assert.Equal(t, "S256", params.Method)
			assert.Equal(t, initVerifier, params.Verifier, "round-trip must preserve verifier")
		})
	}
}

func TestPKCEStore_CookieAttributes(t *testing.T) {
	t.Parallel()

	store := newTestPKCEStore(t)
	rec := httptest.NewRecorder()
	_, err := store.InitVerifier(context.Background(), rec, "state-x")
	require.NoError(t, err)

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]

	assert.True(t, c.HttpOnly, "PKCE cookie must be HttpOnly")
	assert.True(t, c.Secure, "PKCE cookie must be Secure")
	assert.Empty(t, c.Domain, "PKCE cookie must be host-only")
	assert.Equal(t, endpoints.PathAuthenticateCallback, c.Path)
	assert.Equal(t, int(pkceCookieTTL.Seconds()), c.MaxAge)
}

func TestPKCEStore_PopClearsCookie(t *testing.T) {
	t.Parallel()

	store := newTestPKCEStore(t)
	initRec := httptest.NewRecorder()
	_, err := store.InitVerifier(context.Background(), initRec, "state-1")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://auth.example/oauth2/callback", nil)
	for _, c := range initRec.Result().Cookies() {
		req.AddCookie(c)
	}

	popRec := httptest.NewRecorder()
	_, err = store.PopVerifier(context.Background(), popRec, req, "state-1")
	require.NoError(t, err)

	cleared := popRec.Result().Cookies()
	require.Len(t, cleared, 1)
	assert.Equal(t, -1, cleared[0].MaxAge, "PopVerifier must clear cookie after use")
}

func TestPKCEStore_DecodeInvalidJSON(t *testing.T) {
	t.Parallel()

	store := newTestPKCEStore(t)
	cookieName := store.cookieNameForState("state-x")

	// Encrypt valid ciphertext containing invalid JSON.
	invalidJSON := []byte("not-json{{{")
	enc := cryptutil.Encrypt(store.cipher, invalidJSON, []byte(cookieName))
	value := base64.RawURLEncoding.EncodeToString(enc)

	_, err := store.decode(cookieName, value)
	require.Error(t, err, "decode must fail for invalid JSON payload")
}

func TestPKCEStore_DecodeInvalidBase64(t *testing.T) {
	t.Parallel()

	store := newTestPKCEStore(t)
	cookieName := store.cookieNameForState("state-x")

	_, err := store.decode(cookieName, "!!!not-base64!!!")
	require.Error(t, err, "decode must fail for invalid base64")
}

func TestPKCEStore_MultipleStates(t *testing.T) {
	t.Parallel()

	store := newTestPKCEStore(t)

	rec1 := httptest.NewRecorder()
	ctx1, err := store.InitVerifier(context.Background(), rec1, "state-1")
	require.NoError(t, err)
	verifier1, _ := pkce.FromContext(ctx1)

	rec2 := httptest.NewRecorder()
	ctx2, err := store.InitVerifier(context.Background(), rec2, "state-2")
	require.NoError(t, err)
	verifier2, _ := pkce.FromContext(ctx2)

	assert.NotEqual(t, verifier1.Verifier, verifier2.Verifier, "each state gets a unique verifier")

	cookies1 := rec1.Result().Cookies()
	cookies2 := rec2.Result().Cookies()
	require.NotEqual(t, cookies1[0].Name, cookies2[0].Name, "each state gets a unique cookie")

	// Pop each independently.
	req := httptest.NewRequest(http.MethodGet, "https://auth.example/oauth2/callback", nil)
	req.AddCookie(cookies1[0])
	req.AddCookie(cookies2[0])

	w1 := httptest.NewRecorder()
	pop1, err := store.PopVerifier(context.Background(), w1, req, "state-1")
	require.NoError(t, err)
	p1, _ := pkce.FromContext(pop1)
	assert.Equal(t, verifier1.Verifier, p1.Verifier)

	w2 := httptest.NewRecorder()
	pop2, err := store.PopVerifier(context.Background(), w2, req, "state-2")
	require.NoError(t, err)
	p2, _ := pkce.FromContext(pop2)
	assert.Equal(t, verifier2.Verifier, p2.Verifier)
}

func TestPKCEStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	store := newTestPKCEStore(t)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(idx int) {
			defer wg.Done()
			state := fmt.Sprintf("state-%d", idx)

			initRec := httptest.NewRecorder()
			initCtx, err := store.InitVerifier(context.Background(), initRec, state)
			if err != nil {
				t.Errorf("init %d: %v", idx, err)
				return
			}
			initParams, _ := pkce.FromContext(initCtx)

			req := httptest.NewRequest(http.MethodGet, "https://auth.example/oauth2/callback", nil)
			for _, c := range initRec.Result().Cookies() {
				req.AddCookie(c)
			}

			popRec := httptest.NewRecorder()
			popCtx, err := store.PopVerifier(context.Background(), popRec, req, state)
			if err != nil {
				t.Errorf("pop %d: %v", idx, err)
				return
			}
			popParams, ok := pkce.FromContext(popCtx)
			if !ok || popParams.Verifier != initParams.Verifier {
				t.Errorf("pop %d: verifier mismatch", idx)
			}
		}(i)
	}
	wg.Wait()
}

type mockPKCEAuthenticator struct {
	identity.MockProvider
	methods []string
}

func (m *mockPKCEAuthenticator) PKCEMethods() []string {
	return m.methods
}

func TestShouldUsePKCE(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		auth identity.Authenticator
		want bool
	}{
		{"nil_provider", nil, false},
		{"no_pkce_interface", &identity.MockProvider{}, false},
		{"s256_supported", &mockPKCEAuthenticator{methods: []string{"S256"}}, true},
		{"s256_case_insensitive", &mockPKCEAuthenticator{methods: []string{"s256"}}, true},
		{"s256_among_others", &mockPKCEAuthenticator{methods: []string{"plain", "S256"}}, true},
		{"only_plain", &mockPKCEAuthenticator{methods: []string{"plain"}}, false},
		{"empty_methods", &mockPKCEAuthenticator{methods: nil}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, shouldUsePKCE(tc.auth))
		})
	}
}

func FuzzPKCEStoreEncodeDecode(f *testing.F) {
	cookieSecret, err := base64.StdEncoding.DecodeString("OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw=")
	if err != nil {
		f.Fatal(err)
	}
	aead, err := cryptutil.NewAEADCipher(cookieSecret)
	if err != nil {
		f.Fatal(err)
	}
	store := &pkceStore{cipher: aead}

	f.Add("my-verifier", int64(1000))
	f.Add("", int64(0))
	f.Add("a-very-long-verifier-string-that-exceeds-normal-lengths-"+
		"abcdefghijklmnopqrstuvwxyz0123456789", int64(9999999999))

	f.Fuzz(func(t *testing.T, verifier string, iat int64) {
		entry := pkceEntry{Verifier: verifier, IssuedAt: iat}
		cookieName := "test_cookie"

		encoded, err := store.encode(cookieName, entry)
		if err != nil {
			return
		}
		decoded, err := store.decode(cookieName, encoded)
		require.NoError(t, err)
		assert.Equal(t, entry.Verifier, decoded.Verifier)
		assert.Equal(t, entry.IssuedAt, decoded.IssuedAt)
	})
}
