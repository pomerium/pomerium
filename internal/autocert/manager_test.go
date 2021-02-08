package autocert

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
)

type M = map[string]interface{}

func newMockACME(srv *httptest.Server) http.Handler {
	var certBuffer bytes.Buffer

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/acme/directory", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(M{
			"keyChange":  srv.URL + "/acme/key-change",
			"newAccount": srv.URL + "/acme/new-acct",
			"newNonce":   srv.URL + "/acme/new-nonce",
			"newOrder":   srv.URL + "/acme/new-order",
			"revokeCert": srv.URL + "/acme/revoke-cert",
		})
	})
	r.Head("/acme/new-nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "NONCE")
		w.WriteHeader(http.StatusOK)
	})
	r.Post("/acme/new-acct", func(w http.ResponseWriter, r *http.Request) {
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
	r.Post("/acme/finalize", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			CSR string `json:"csr"`
		}
		readJWSPayload(r.Body, &payload)
		bs, _ := base64.RawURLEncoding.DecodeString(payload.CSR)
		csr, _ := x509.ParseCertificateRequest(bs)
		caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
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
		}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, csr.PublicKey, caKey)
		certBuffer.Reset()
		_ = pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: der})

		w.Header().Set("Replay-Nonce", "NONCE")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(M{
			"status":      "valid",
			"finalize":    srv.URL + "/acme/finalize",
			"certificate": srv.URL + "/acme/certificate",
		})
	})
	r.Post("/acme/certificate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "NONCE")
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(certBuffer.Bytes())
	})
	return r
}

func TestConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mockACME http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockACME.ServeHTTP(w, r)
	}))
	defer srv.Close()
	mockACME = newMockACME(srv)

	tmpdir := filepath.Join(os.TempDir(), uuid.New().String())
	_ = os.MkdirAll(tmpdir, 0o755)
	defer os.RemoveAll(tmpdir)

	li, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	addr := li.Addr().String()
	_ = li.Close()

	to, err := config.ParseWeightedUrls("http://to.example.com")
	require.NoError(t, err)

	p1 := config.Policy{
		From: "http://from.example.com", To: to,
	}
	_ = p1.Validate()

	mgr, err := newManager(ctx, config.NewStaticSource(&config.Config{
		Options: &config.Options{
			AutocertOptions: config.AutocertOptions{
				Enable:     true,
				UseStaging: true,
				MustStaple: false,
				Folder:     tmpdir,
			},
			HTTPRedirectAddr: addr,
			Policies:         []config.Policy{p1},
		},
	}), certmagic.ACMEManager{
		CA:     srv.URL + "/acme/directory",
		TestCA: srv.URL + "/acme/directory",
	}, time.Second)
	if !assert.NoError(t, err) {
		return
	}

	var certs []tls.Certificate
	for i := 0; i < 10; i++ {
		cfg := mgr.GetConfig()
		assert.LessOrEqual(t, len(cfg.AutoCertificates), 1)
		if len(cfg.AutoCertificates) == 1 && certs == nil {
			certs = cfg.AutoCertificates
		}

		if !cmp.Equal(certs, cfg.AutoCertificates) {
			return
		}

		time.Sleep(time.Second)
	}
	t.Fatalf("expected renewed certs, but certs never changed")
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
			Headers: map[string]string{
				"X-Frame-Options":           "SAMEORIGIN",
				"X-XSS-Protection":          "1; mode=block",
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
			},
		},
	})
	_, err = New(src)
	if !assert.NoError(t, err) {
		return
	}
	err = waitFor(addr)
	if !assert.NoError(t, err) {
		return
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	res, err := client.Get(fmt.Sprintf("http://%s", addr))
	if !assert.NoError(t, err) {
		return
	}
	defer res.Body.Close()

	assert.Equal(t, http.StatusMovedPermanently, res.StatusCode, "should redirect to https")
	for k, v := range src.GetConfig().Options.Headers {
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

func readJWSPayload(r io.Reader, dst interface{}) {
	var req struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	_ = json.NewDecoder(r).Decode(&req)

	bs, _ := base64.RawURLEncoding.DecodeString(req.Payload)
	_ = json.Unmarshal(bs, dst)
}
