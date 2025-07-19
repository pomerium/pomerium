package autocert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/mholt/acmez/v3/acme"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
)

type M = map[string]any

type testCA struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	certPEM []byte
}

func newTestCA() (*testCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute * 10),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &testCA{
		key,
		cert,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

func newMockACME(ca *testCA, srv *httptest.Server) http.Handler {
	var certBuffer bytes.Buffer

	var certs []*x509.Certificate
	findCert := func(serial *big.Int) *x509.Certificate {
		for _, c := range certs {
			if c.SerialNumber.Cmp(serial) == 0 {
				return c
			}
		}
		return nil
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/acme/directory", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(M{
			"keyChange":  srv.URL + "/acme/key-change",
			"newAccount": srv.URL + "/acme/new-acct",
			"newNonce":   srv.URL + "/acme/new-nonce",
			"newOrder":   srv.URL + "/acme/new-order",
			"revokeCert": srv.URL + "/acme/revoke-cert",
		})
	})
	r.Head("/acme/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "NONCE")
		w.WriteHeader(http.StatusOK)
	})
	r.Post("/acme/new-acct", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "NONCE")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(M{
			"status": "valid",
		})
	})
	r.Post("/acme/new-order", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Identifiers []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"identifiers"`
		}
		readJWSPayload(r.Body, &payload)
		w.Header().Set("Replay-Nonce", "NONCE")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(M{
			"status":   "pending",
			"finalize": srv.URL + "/acme/finalize",
		})
	})
	r.Post("/ocsp/request", func(w http.ResponseWriter, r *http.Request) {
		reqData, _ := io.ReadAll(r.Body)
		ocspReq, _ := ocsp.ParseRequest(reqData)
		ocspResp := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: ocspReq.SerialNumber,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(time.Second),
		}

		cert := findCert(ocspReq.SerialNumber)
		data, _ := ocsp.CreateResponse(ca.cert, cert, ocspResp, ca.key)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
	r.Post("/acme/finalize", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			CSR string `json:"csr"`
		}
		readJWSPayload(r.Body, &payload)
		bs, _ := base64.RawURLEncoding.DecodeString(payload.CSR)
		csr, _ := x509.ParseCertificateRequest(bs)
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().Unix()),
			DNSNames:     csr.DNSNames,
			IPAddresses:  csr.IPAddresses,
			Subject: pkix.Name{
				CommonName: csr.DNSNames[0],
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Second * 2),

			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			IsCA:                  false,

			IssuingCertificateURL: []string{srv.URL + "/certs/ca"},
			OCSPServer:            []string{srv.URL + "/ocsp/request"},
		}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, ca.cert, csr.PublicKey, ca.key)
		certBuffer.Reset()
		_ = pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		cert, _ := x509.ParseCertificate(der)
		certs = append(certs, cert)

		w.Header().Set("Replay-Nonce", "NONCE")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(M{
			"status":      "valid",
			"finalize":    srv.URL + "/acme/finalize",
			"certificate": srv.URL + "/acme/certificate",
		})
	})
	r.Post("/acme/certificate", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "NONCE")
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(certBuffer.Bytes())
	})
	r.Get("/certs/ca", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ca.cert.Raw)
	})
	return r
}

func TestConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var mockACME http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockACME.ServeHTTP(w, r)
	}))
	defer srv.Close()

	ca, err := newTestCA()
	require.NoError(t, err)

	mockACME = newMockACME(ca, srv)

	// avoid using t.TempDir so tests don't fail: https://github.com/pomerium/pomerium/issues/4757
	tmpdir := filepath.Join(os.TempDir(), uuid.New().String())
	_ = os.MkdirAll(tmpdir, 0o755)
	defer os.RemoveAll(tmpdir)

	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := li.Addr().String()
	_ = li.Close()

	to, err := config.ParseWeightedUrls("http://to.example.com")
	require.NoError(t, err)

	p1 := config.Policy{
		From: "https://from.example.com", To: to,
	}
	_ = p1.Validate()

	mgr, err := newManager(ctx, config.NewStaticSource(&config.Config{
		Options: &config.Options{
			AutocertOptions: config.AutocertOptions{
				Enable:     true,
				UseStaging: true,
				Email:      "pomerium-test@example.com",
				MustStaple: true,
				Folder:     tmpdir,
			},
			HTTPRedirectAddr: addr,
			Policies:         []config.Policy{p1},
		},
	}), certmagic.ACMEIssuer{
		CA:     srv.URL + "/acme/directory",
		TestCA: srv.URL + "/acme/directory",
	}, time.Millisecond*100)
	if !assert.NoError(t, err) {
		return
	}

	domainRenewed := make(chan bool)
	ocspUpdated := make(chan bool)

	var initialOCSPStaple []byte
	var certValidTime *time.Time
	mgr.OnConfigChange(ctx, func(ctx context.Context, cfg *config.Config) {
		if len(cfg.AutoCertificates) == 0 {
			return
		}

		cert := cfg.AutoCertificates[0]
		if initialOCSPStaple == nil {
			initialOCSPStaple = cert.OCSPStaple
		} else {
			if !bytes.Equal(initialOCSPStaple, cert.OCSPStaple) {
				log.Ctx(ctx).Info().Msg("OCSP updated")
				ocspUpdated <- true
			}
		}
		if certValidTime == nil {
			certValidTime = &cert.Leaf.NotAfter
		} else {
			if !certValidTime.Equal(cert.Leaf.NotAfter) {
				log.Ctx(ctx).Info().Msg("domain renewed")
				domainRenewed <- true
			}
		}
	})

	domainRenewedOK := false
	ocspUpdatedOK := false

	for !domainRenewedOK || !ocspUpdatedOK {
		select {
		case <-time.After(time.Second * 10):
			t.Error("timeout waiting for certs renewal")
			return
		case domainRenewedOK = <-domainRenewed:
		case ocspUpdatedOK = <-ocspUpdated:
		}
	}
}

func TestRedirect(t *testing.T) {
	li, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	addr := li.Addr().String()
	_ = li.Close()

	src := config.NewStaticSource(&config.Config{
		Options: &config.Options{
			HTTPRedirectAddr: addr,
			SetResponseHeaders: map[string]string{
				"X-Frame-Options":           "SAMEORIGIN",
				"X-XSS-Protection":          "1; mode=block",
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
			},
		},
	})
	_, err = New(t.Context(), src)
	if !assert.NoError(t, err) {
		return
	}
	err = waitFor(addr)
	if !assert.NoError(t, err) {
		return
	}

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	res, err := client.Get(fmt.Sprintf("http://%s", addr))
	if !assert.NoError(t, err) {
		return
	}
	defer res.Body.Close()

	assert.Equal(t, http.StatusMovedPermanently, res.StatusCode, "should redirect to https")
	for k, v := range src.GetConfig().Options.SetResponseHeaders {
		assert.NotEqual(t, v, res.Header.Get(k), "should ignore options header")
	}
}

func waitFor(addr string) error {
	var err error
	deadline := time.Now().Add(time.Second * 30)
	for time.Now().Before(deadline) {
		var conn net.Conn
		conn, err = net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(time.Second)
	}
	return err
}

func readJWSPayload(r io.Reader, dst any) {
	var req struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	_ = json.NewDecoder(r).Decode(&req)

	bs, _ := base64.RawURLEncoding.DecodeString(req.Payload)
	_ = json.Unmarshal(bs, dst)
}

func newACMEIssuer() *certmagic.ACMEIssuer {
	return &certmagic.ACMEIssuer{
		CA:     certmagic.DefaultACME.CA,
		TestCA: certmagic.DefaultACME.TestCA,
	}
}

func Test_configureCertificateAuthority(t *testing.T) {
	type args struct {
		acmeMgr *certmagic.ACMEIssuer
		opts    config.AutocertOptions
	}
	type test struct {
		args     args
		expected *certmagic.ACMEIssuer
		wantErr  bool
	}
	tests := map[string]func(t *testing.T) test{
		"ok/default": func(_ *testing.T) test {
			return test{
				args: args{
					acmeMgr: newACMEIssuer(),
					opts:    config.AutocertOptions{},
				},
				expected: &certmagic.ACMEIssuer{
					Agreed: true,
					CA:     certmagic.DefaultACME.CA,
					Email:  " ",
					TestCA: certmagic.DefaultACME.TestCA,
				},
				wantErr: false,
			}
		},
		"ok/staging": func(_ *testing.T) test {
			return test{
				args: args{
					acmeMgr: newACMEIssuer(),
					opts: config.AutocertOptions{
						UseStaging: true,
					},
				},
				expected: &certmagic.ACMEIssuer{
					Agreed: true,
					CA:     certmagic.DefaultACME.TestCA,
					Email:  " ",
					TestCA: certmagic.DefaultACME.TestCA,
				},
				wantErr: false,
			}
		},
		"ok/custom-ca-staging": func(_ *testing.T) test {
			return test{
				args: args{
					acmeMgr: newACMEIssuer(),
					opts: config.AutocertOptions{
						CA:         "test-ca.example.com/directory",
						Email:      "test@example.com",
						UseStaging: true,
					},
				},
				expected: &certmagic.ACMEIssuer{
					Agreed: true,
					CA:     "test-ca.example.com/directory",
					Email:  "test@example.com",
					TestCA: certmagic.DefaultACME.TestCA,
				},
				wantErr: false,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			if err := configureCertificateAuthority(tc.args.acmeMgr, tc.args.opts); (err != nil) != tc.wantErr {
				t.Errorf("configureCertificateAuthority() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !cmp.Equal(tc.expected, tc.args.acmeMgr, cmpopts.IgnoreUnexported(certmagic.ACMEIssuer{})) {
				t.Errorf("configureCertificateAuthority() diff = %s", cmp.Diff(tc.expected, tc.args.acmeMgr, cmpopts.IgnoreUnexported(certmagic.ACMEIssuer{})))
			}
		})
	}
}

func Test_configureExternalAccountBinding(t *testing.T) {
	type args struct {
		acmeMgr *certmagic.ACMEIssuer
		opts    config.AutocertOptions
	}
	type test struct {
		args     args
		expected *certmagic.ACMEIssuer
		wantErr  bool
	}
	tests := map[string]func(t *testing.T) test{
		"ok": func(_ *testing.T) test {
			return test{
				args: args{
					acmeMgr: newACMEIssuer(),
					opts: config.AutocertOptions{
						EABKeyID:  "keyID",
						EABMACKey: "29D7t6-mOuEV5vvBRX0UYF5T7x6fomidhM1kMJco-yw",
					},
				},
				expected: &certmagic.ACMEIssuer{
					CA:     certmagic.DefaultACME.CA,
					TestCA: certmagic.DefaultACME.TestCA,
					ExternalAccount: &acme.EAB{
						KeyID:  "keyID",
						MACKey: "29D7t6-mOuEV5vvBRX0UYF5T7x6fomidhM1kMJco-yw",
					},
				},
				wantErr: false,
			}
		},
		"fail/error-decoding-mac-key": func(_ *testing.T) test {
			return test{
				args: args{
					acmeMgr: newACMEIssuer(),
					opts: config.AutocertOptions{
						EABKeyID:  "keyID",
						EABMACKey: ">invalid-base-64-data<",
					},
				},
				wantErr: true,
			}
		},
	}

	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			err := configureExternalAccountBinding(tc.args.acmeMgr, tc.args.opts)
			if (err != nil) != tc.wantErr {
				t.Errorf("configureExternalAccountBinding() error = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && !cmp.Equal(tc.expected, tc.args.acmeMgr, cmpopts.IgnoreUnexported(certmagic.ACMEIssuer{})) {
				t.Errorf("configureCertificateAuthority() diff = %s", cmp.Diff(tc.expected, tc.args.acmeMgr, cmpopts.IgnoreUnexported(certmagic.ACMEIssuer{})))
			}
		})
	}
}

func Test_configureTrustedRoots(t *testing.T) {
	ca, err := newTestCA()
	require.NoError(t, err)
	type args struct {
		acmeMgr *certmagic.ACMEIssuer
		opts    config.AutocertOptions
	}
	type test struct {
		args     args
		expected *certmagic.ACMEIssuer
		wantErr  bool
		cleanup  func()
	}
	tests := map[string]func(t *testing.T) test{
		"ok/pem": func(t *testing.T) test {
			roots, err := x509.SystemCertPool()
			require.NoError(t, err)
			ok := roots.AppendCertsFromPEM(ca.certPEM)
			require.Equal(t, true, ok)
			return test{
				args: args{
					acmeMgr: newACMEIssuer(),
					opts: config.AutocertOptions{
						TrustedCA: base64.StdEncoding.EncodeToString(ca.certPEM),
					},
				},
				expected: &certmagic.ACMEIssuer{
					CA:           certmagic.DefaultACME.CA,
					TestCA:       certmagic.DefaultACME.TestCA,
					TrustedRoots: roots,
				},
				wantErr: false,
			}
		},
		"ok/file": func(t *testing.T) test {
			roots, err := x509.SystemCertPool()
			require.NoError(t, err)
			ok := roots.AppendCertsFromPEM(ca.certPEM)
			require.Equal(t, true, ok)
			f, err := os.CreateTemp(t.TempDir(), "pomerium-test-ca")
			require.NoError(t, err)
			n, err := f.Write(ca.certPEM)
			require.NoError(t, err)
			require.Equal(t, len(ca.certPEM), n)
			return test{
				args: args{
					acmeMgr: newACMEIssuer(),
					opts: config.AutocertOptions{
						TrustedCAFile: f.Name(),
					},
				},
				expected: &certmagic.ACMEIssuer{
					CA:           certmagic.DefaultACME.CA,
					TestCA:       certmagic.DefaultACME.TestCA,
					TrustedRoots: roots,
				},
				wantErr: false,
				cleanup: func() {
					os.Remove(f.Name())
				},
			}
		},
		"fail/pem": func(t *testing.T) test {
			roots, err := x509.SystemCertPool()
			require.NoError(t, err)
			return test{
				args: args{
					acmeMgr: newACMEIssuer(),
					opts: config.AutocertOptions{
						TrustedCA: ">invalid-base-64-ca-pem<",
					},
				},
				expected: &certmagic.ACMEIssuer{
					CA:           certmagic.DefaultACME.CA,
					TestCA:       certmagic.DefaultACME.TestCA,
					TrustedRoots: roots,
				},
				wantErr: true,
			}
		},
		"fail/file": func(t *testing.T) test {
			roots, err := x509.SystemCertPool()
			require.NoError(t, err)
			return test{
				args: args{
					acmeMgr: newACMEIssuer(),
					opts: config.AutocertOptions{
						TrustedCAFile: "some-non-existing-file",
					},
				},
				expected: &certmagic.ACMEIssuer{
					CA:           certmagic.DefaultACME.CA,
					TestCA:       certmagic.DefaultACME.TestCA,
					TrustedRoots: roots,
				},
				wantErr: true,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			err := configureTrustedRoots(tc.args.acmeMgr, tc.args.opts)
			if (err != nil) != tc.wantErr {
				t.Errorf("configureTrustedRoots() error = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && !cmp.Equal(tc.expected, tc.args.acmeMgr, cmpopts.IgnoreUnexported(certmagic.ACMEIssuer{}, x509.CertPool{})) {
				t.Errorf("configureCertificateAuthority() diff = %s", cmp.Diff(tc.expected, tc.args.acmeMgr, cmpopts.IgnoreUnexported(certmagic.ACMEIssuer{}, x509.CertPool{})))
			}
			if err == nil && !cmp.Equal(tc.expected.TrustedRoots.Subjects(), tc.args.acmeMgr.TrustedRoots.Subjects()) {
				t.Errorf("configureCertificateAuthority() subjects diff = %s", cmp.Diff(tc.expected.TrustedRoots.Subjects(), tc.args.acmeMgr.TrustedRoots.Subjects()))
			}
			if tc.cleanup != nil {
				tc.cleanup()
			}
		})
	}
}

func Test_sourceHostnames(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.Policies = []config.Policy{
		{From: "https://foo.example.com"},
		{From: "http://non-https-route.example.com"},
		{From: "https://bar.example.com:5443"},
		{From: "ssh://ssh-hostname"},
		{From: "tcp+https://baz.example.com:1234"},
		{From: "udp+https://quux.example.com:5678"},
	}

	assert.ElementsMatch(t, []string{
		"foo.example.com",
		"bar.example.com",
		"baz.example.com",
		"quux.example.com",
	}, sourceHostnames(cfg))
}

func TestShouldEnableHTTPChallenge(t *testing.T) {
	t.Parallel()

	assert.False(t, shouldEnableHTTPChallenge(nil))
	assert.False(t, shouldEnableHTTPChallenge(&config.Config{}))
	assert.False(t, shouldEnableHTTPChallenge(&config.Config{Options: &config.Options{}}))
	assert.False(t, shouldEnableHTTPChallenge(&config.Config{Options: &config.Options{
		HTTPRedirectAddr: ":8080",
	}}))
	assert.False(t, shouldEnableHTTPChallenge(&config.Config{Options: &config.Options{
		HTTPRedirectAddr: "127.0.0.1:8080",
	}}))
	assert.True(t, shouldEnableHTTPChallenge(&config.Config{Options: &config.Options{
		HTTPRedirectAddr: ":80",
	}}))
	assert.True(t, shouldEnableHTTPChallenge(&config.Config{Options: &config.Options{
		HTTPRedirectAddr: "127.0.0.1:80",
	}}))
}
