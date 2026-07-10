package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/authenticateflow"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/postgresapi"
)

func TestCreatePostgresSessionBinding(t *testing.T) {
	p, opts, idpID := newPostgresBindingTestProxy(t)
	fake := &fakePostgresBindingFlow{binding: &session.SessionBinding{
		ExpiresAt: timestamppb.New(time.Now().Add(30 * time.Minute)),
	}}
	p.state.Load().authenticateFlow = fake

	handle := &session.Handle{
		Id:                 "session-id",
		UserId:             "user-id",
		IdentityProviderId: idpID,
		Iss:                new("authenticate.example.com"),
		Aud:                []string{"control.example.com"},
		Iat:                timestamppb.Now(),
	}
	rawSessionHandle := encodeSessionHandle(t, opts, handle)
	certificate := newProxyPostgresCertificate(t, "db.example.com")
	request := newSignedPostgresBindingRequest(t, "DB.EXAMPLE.COM", rawSessionHandle, certificate)
	body, err := json.Marshal(request)
	require.NoError(t, err)
	httpRequest := httptest.NewRequest(http.MethodPost, "https://control.example.com"+postgresapi.SessionBindingsPath, bytes.NewReader(body))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer Pomerium-"+rawSessionHandle)
	w := httptest.NewRecorder()
	httputil.HandlerFunc(p.createPostgresSessionBinding).ServeHTTP(w, httpRequest)

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	require.Equal(t, idpID, fake.expectedIDP)
	require.Equal(t, "db.example.com", fake.routeHostname)
	require.Equal(t, "session-id", fake.handle.GetId())
	require.Contains(t, fake.bindingID, "postgrescert-SHA256:")
	var response postgresapi.CreateSessionBindingResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	require.Equal(t, fake.bindingID, response.BindingID)
}

func TestCreatePostgresSessionBindingProofBindsRouteHandleAndCertificate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(
			t *testing.T,
			request *postgresapi.CreateSessionBindingRequest,
			certificate, otherCertificate *proxyPostgresCertificate,
			rawSessionHandle, otherRawSessionHandle string,
		) string
	}{
		{
			name: "wrong key",
			mutate: func(t *testing.T, request *postgresapi.CreateSessionBindingRequest, certificate, otherCertificate *proxyPostgresCertificate, rawSessionHandle, _ string) string {
				request.ProofSignature = signPostgresBindingProof(t, request.RouteHost, rawSessionHandle, certificate.Certificate.Raw, otherCertificate.PrivateKey)
				return rawSessionHandle
			},
		},
		{
			name: "wrong route",
			mutate: func(t *testing.T, request *postgresapi.CreateSessionBindingRequest, certificate, _ *proxyPostgresCertificate, rawSessionHandle, _ string) string {
				request.ProofSignature = signPostgresBindingProof(t, "other.example.com", rawSessionHandle, certificate.Certificate.Raw, certificate.PrivateKey)
				return rawSessionHandle
			},
		},
		{
			name: "wrong handle",
			mutate: func(t *testing.T, request *postgresapi.CreateSessionBindingRequest, certificate, _ *proxyPostgresCertificate, rawSessionHandle, otherRawSessionHandle string) string {
				request.ProofSignature = signPostgresBindingProof(t, request.RouteHost, otherRawSessionHandle, certificate.Certificate.Raw, certificate.PrivateKey)
				return rawSessionHandle
			},
		},
		{
			name: "wrong certificate",
			mutate: func(t *testing.T, request *postgresapi.CreateSessionBindingRequest, certificate, otherCertificate *proxyPostgresCertificate, rawSessionHandle, _ string) string {
				request.ProofSignature = signPostgresBindingProof(t, request.RouteHost, rawSessionHandle, otherCertificate.Certificate.Raw, certificate.PrivateKey)
				return rawSessionHandle
			},
		},
		{
			name: "malformed base64",
			mutate: func(_ *testing.T, request *postgresapi.CreateSessionBindingRequest, _ *proxyPostgresCertificate, _ *proxyPostgresCertificate, rawSessionHandle, _ string) string {
				request.ProofSignature = "%not-base64%"
				return rawSessionHandle
			},
		},
		{
			name: "padded base64",
			mutate: func(t *testing.T, request *postgresapi.CreateSessionBindingRequest, _ *proxyPostgresCertificate, _ *proxyPostgresCertificate, rawSessionHandle, _ string) string {
				signature, err := base64.RawStdEncoding.DecodeString(request.ProofSignature)
				require.NoError(t, err)
				request.ProofSignature = base64.StdEncoding.EncodeToString(signature)
				return rawSessionHandle
			},
		},
		{
			name: "base64 with newline",
			mutate: func(_ *testing.T, request *postgresapi.CreateSessionBindingRequest, _ *proxyPostgresCertificate, _ *proxyPostgresCertificate, rawSessionHandle, _ string) string {
				request.ProofSignature = request.ProofSignature[:8] + "\n" + request.ProofSignature[8:]
				return rawSessionHandle
			},
		},
		{
			name: "wrong signature length",
			mutate: func(_ *testing.T, request *postgresapi.CreateSessionBindingRequest, _ *proxyPostgresCertificate, _ *proxyPostgresCertificate, rawSessionHandle, _ string) string {
				request.ProofSignature = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize-1))
				return rawSessionHandle
			},
		},
		{
			name: "replay to another session",
			mutate: func(_ *testing.T, _ *postgresapi.CreateSessionBindingRequest, _ *proxyPostgresCertificate, _ *proxyPostgresCertificate, _ string, otherRawSessionHandle string) string {
				return otherRawSessionHandle
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, opts, idpID := newPostgresBindingTestProxy(t)
			fake := &fakePostgresBindingFlow{binding: &session.SessionBinding{
				ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
			}}
			p.state.Load().authenticateFlow = fake
			newHandle := func(id string) *session.Handle {
				return &session.Handle{
					Id: id, UserId: "user-id", IdentityProviderId: idpID,
					Iss: new("authenticate.example.com"), Aud: []string{"control.example.com"}, Iat: timestamppb.Now(),
				}
			}
			rawSessionHandle := encodeSessionHandle(t, opts, newHandle("session-id"))
			otherRawSessionHandle := encodeSessionHandle(t, opts, newHandle("other-session-id"))
			certificate := newProxyPostgresCertificate(t, "db.example.com")
			otherCertificate := newProxyPostgresCertificate(t, "db.example.com")
			request := newSignedPostgresBindingRequest(t, "db.example.com", rawSessionHandle, certificate)
			authorizationHandle := tc.mutate(
				t, &request, certificate, otherCertificate, rawSessionHandle, otherRawSessionHandle)
			body, err := json.Marshal(request)
			require.NoError(t, err)
			r := httptest.NewRequest(http.MethodPost, "https://control.example.com"+postgresapi.SessionBindingsPath, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer Pomerium-"+authorizationHandle)
			w := httptest.NewRecorder()
			httputil.HandlerFunc(p.createPostgresSessionBinding).ServeHTTP(w, r)

			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			require.NotContains(t, w.Body.String(), rawSessionHandle)
			require.NotContains(t, w.Body.String(), authorizationHandle)
			require.NotContains(t, w.Body.String(), request.CertificatePEM)
			require.NotContains(t, w.Body.String(), request.ProofSignature)
			require.Nil(t, fake.handle, "invalid proof must not reach binding persistence")
		})
	}
}

func TestCreatePostgresSessionBindingRequiresExactFreshBearer(t *testing.T) {
	p, opts, idpID := newPostgresBindingTestProxy(t)
	p.state.Load().authenticateFlow = &fakePostgresBindingFlow{binding: &session.SessionBinding{
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}}
	body, err := json.Marshal(postgresapi.CreateSessionBindingRequest{
		RouteHost:      "db.example.com",
		CertificatePEM: string(newProxyPostgresCertificatePEM(t, "db.example.com")),
	})
	require.NoError(t, err)

	tests := []struct {
		name   string
		handle *session.Handle
		cookie bool
	}{
		{"cookie only", nil, true},
		{"stale", &session.Handle{Id: "session-id", UserId: "user-id", IdentityProviderId: idpID, Iss: new("authenticate.example.com"), Aud: []string{"control.example.com"}, Iat: timestamppb.New(time.Now().Add(-6 * time.Minute))}, false},
		{"wrong issuer", &session.Handle{Id: "session-id", UserId: "user-id", IdentityProviderId: idpID, Iss: new("other.example.com"), Aud: []string{"control.example.com"}, Iat: timestamppb.Now()}, false},
		{"wrong audience", &session.Handle{Id: "session-id", UserId: "user-id", IdentityProviderId: idpID, Iss: new("authenticate.example.com"), Aud: []string{"other.example.com"}, Iat: timestamppb.Now()}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://control.example.com"+postgresapi.SessionBindingsPath, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			if tc.handle != nil {
				r.Header.Set("Authorization", "Bearer Pomerium-"+encodeSessionHandle(t, opts, tc.handle))
			}
			if tc.cookie {
				r.AddCookie(&http.Cookie{Name: opts.CookieName, Value: encodeSessionHandle(t, opts, &session.Handle{Id: "session-id"})})
			}
			w := httptest.NewRecorder()
			httputil.HandlerFunc(p.createPostgresSessionBinding).ServeHTTP(w, r)
			require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
		})
	}
}

func TestCreatePostgresSessionBindingStrictBodyAndStatelessFailure(t *testing.T) {
	p, opts, idpID := newPostgresBindingTestProxy(t)
	fake := &fakePostgresBindingFlow{err: authenticateflow.ErrPostgresSessionBindingUnsupported}
	p.state.Load().authenticateFlow = fake
	rawSessionHandle := encodeSessionHandle(t, opts, &session.Handle{
		Id: "session-id", UserId: "user-id", IdentityProviderId: idpID,
		Iss: new("authenticate.example.com"), Aud: []string{"control.example.com"}, Iat: timestamppb.Now(),
	})
	authorization := "Bearer Pomerium-" + rawSessionHandle

	t.Run("unknown field", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "https://control.example.com"+postgresapi.SessionBindingsPath,
			bytes.NewBufferString(`{"route_host":"db.example.com","certificate_pem":"x","unknown":true}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		httputil.HandlerFunc(p.createPostgresSessionBinding).ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("oversized body", func(t *testing.T) {
		body := append([]byte(`{"route_host":"db.example.com","certificate_pem":"`),
			bytes.Repeat([]byte("x"), postgresapi.MaxCreateSessionBindingRequestBytes)...)
		body = append(body, []byte(`"}`)...)
		r := httptest.NewRequest(http.MethodPost, "https://control.example.com"+postgresapi.SessionBindingsPath, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		httputil.HandlerFunc(p.createPostgresSessionBinding).ServeHTTP(w, r)
		require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	})

	t.Run("stateless", func(t *testing.T) {
		certificate := newProxyPostgresCertificate(t, "db.example.com")
		request := newSignedPostgresBindingRequest(t, "db.example.com", rawSessionHandle, certificate)
		body, err := json.Marshal(request)
		require.NoError(t, err)
		r := httptest.NewRequest(http.MethodPost, "https://control.example.com"+postgresapi.SessionBindingsPath, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		httputil.HandlerFunc(p.createPostgresSessionBinding).ServeHTTP(w, r)
		require.Equal(t, http.StatusPreconditionFailed, w.Code, w.Body.String())
	})
}

func TestProgrammaticLoginSelectsPostgresRouteIdentityProvider(t *testing.T) {
	p, _, idpID := newPostgresBindingTestProxy(t)
	redirect := &url.URL{Scheme: "https", Host: "control.example.com", Path: "/.pomerium/api/v1/login"}
	query := redirect.Query()
	query.Set("pomerium_redirect_uri", "http://localhost")
	query.Set(postgresapi.LoginRouteQuery, "db.example.com")
	redirect.RawQuery = query.Encode()
	r := httptest.NewRequest(http.MethodGet, redirect.String(), nil)
	w := httptest.NewRecorder()
	require.NoError(t, p.ProgrammaticLogin(w, r))
	require.Equal(t, http.StatusOK, w.Code)
	signInURL, err := url.Parse(w.Body.String())
	require.NoError(t, err)
	require.Equal(t, idpID, signInURL.Query().Get("pomerium_idp_id"))
	require.NotEmpty(t, signInURL.Query().Get("pomerium_signature"))
}

func newPostgresBindingTestProxy(t *testing.T) (*Proxy, *config.Options, string) {
	t.Helper()
	opts := testOptions(t)
	opts.AuthenticateURLString = "https://authenticate.example.com"
	opts.RuntimeFlags[config.RuntimeFlagPostgres] = true
	to, err := config.ParseWeightedUrls("postgres://upstream:secret@postgres.internal:5432/database")
	require.NoError(t, err)
	opts.Routes = []config.Policy{{
		From:        "postgres://db.example.com",
		To:          to,
		IDPClientID: "postgres-route-client-id",
	}}
	cfg := config.New(opts)
	p, err := New(t.Context(), cfg)
	require.NoError(t, err)
	p.currentConfig.Store(cfg)
	idp, err := opts.GetIdentityProviderForPolicy(&opts.Routes[0])
	require.NoError(t, err)
	return p, opts, idp.GetId()
}

type fakePostgresBindingFlow struct {
	handle        *session.Handle
	expectedIDP   string
	bindingID     string
	routeHostname string
	binding       *session.SessionBinding
	err           error
}

func (f *fakePostgresBindingFlow) AuthenticateSignInURL(context.Context, url.Values, *url.URL, string, []string) (string, error) {
	return "", nil
}
func (f *fakePostgresBindingFlow) Callback(http.ResponseWriter, *http.Request) error { return nil }
func (f *fakePostgresBindingFlow) GetSessionBindingInfo(http.ResponseWriter, *http.Request, *session.Handle) error {
	return nil
}

func (f *fakePostgresBindingFlow) RevokeSessionBinding(http.ResponseWriter, *http.Request, *session.Handle) error {
	return nil
}

func (f *fakePostgresBindingFlow) RevokeIdentityBinding(http.ResponseWriter, *http.Request, *session.Handle) error {
	return nil
}

func (f *fakePostgresBindingFlow) CreatePostgresSessionBinding(_ context.Context, h *session.Handle, expectedIDP, bindingID, routeHostname string, _ time.Time) (*session.SessionBinding, error) {
	f.handle = h
	f.expectedIDP = expectedIDP
	f.bindingID = bindingID
	f.routeHostname = routeHostname
	return f.binding, f.err
}

type proxyPostgresCertificate struct {
	PEM         []byte
	Certificate *x509.Certificate
	PrivateKey  ed25519.PrivateKey
}

func newProxyPostgresCertificatePEM(t testing.TB, hostname string) []byte {
	t.Helper()
	return newProxyPostgresCertificate(t, hostname).PEM
}

func newProxyPostgresCertificate(t testing.TB, hostname string) *proxyPostgresCertificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pomerium-postgres-client"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, DNSNames: []string{hostname},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &proxyPostgresCertificate{
		PEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Certificate: certificate,
		PrivateKey:  privateKey,
	}
}

func newSignedPostgresBindingRequest(
	t testing.TB,
	routeHostname, rawSessionHandle string,
	certificate *proxyPostgresCertificate,
) postgresapi.CreateSessionBindingRequest {
	t.Helper()
	return postgresapi.CreateSessionBindingRequest{
		RouteHost:      routeHostname,
		CertificatePEM: string(certificate.PEM),
		ProofSignature: signPostgresBindingProof(
			t, routeHostname, rawSessionHandle, certificate.Certificate.Raw, certificate.PrivateKey),
	}
}

func signPostgresBindingProof(
	t testing.TB,
	routeHostname, rawSessionHandle string,
	certificateDER []byte,
	privateKey ed25519.PrivateKey,
) string {
	t.Helper()
	message, err := postgresapi.SessionBindingProofMessage(routeHostname, rawSessionHandle, certificateDER)
	require.NoError(t, err)
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, message))
}

var _ authenticateFlow = (*fakePostgresBindingFlow)(nil)
