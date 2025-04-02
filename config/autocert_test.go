package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newCACertPEM() ([]byte, error) {
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

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func TestAutocertOptions_Validate(t *testing.T) {
	certPEM, err := newCACertPEM()
	require.NoError(t, err)

	type fields struct {
		Enable        bool
		CA            string
		Email         string
		UseStaging    bool
		EABKeyID      string
		EABMACKey     string
		MustStaple    bool
		Folder        string
		TrustedCA     string
		TrustedCAFile string
	}
	type test struct {
		fields  fields
		wantErr bool
		cleanup func()
	}
	tests := map[string]func(t *testing.T) test{
		"ok/custom-ca": func(_ *testing.T) test {
			return test{
				fields: fields{
					CA: "test-ca.example.com/directory",
				},
				wantErr: false,
			}
		},
		"ok/eab": func(_ *testing.T) test {
			return test{
				fields: fields{
					EABKeyID:  "keyID",
					EABMACKey: "29D7t6-mOuEV5vvBRX0UYF5T7x6fomidhM1kMJco-yw",
				},
				wantErr: false,
			}
		},
		"ok/trusted-ca": func(_ *testing.T) test {
			return test{
				fields: fields{
					TrustedCA: base64.StdEncoding.EncodeToString(certPEM),
				},
				wantErr: false,
			}
		},
		"ok/trusted-ca-file": func(t *testing.T) test {
			f, err := os.CreateTemp(t.TempDir(), "pomerium-test-ca")
			require.NoError(t, err)
			n, err := f.Write(certPEM)
			require.NoError(t, err)
			require.Equal(t, len(certPEM), n)
			return test{
				fields: fields{
					TrustedCAFile: f.Name(),
				},
				wantErr: false,
				cleanup: func() { os.Remove(f.Name()) },
			}
		},
		"fail/missing-eab-key": func(_ *testing.T) test {
			return test{
				fields: fields{
					EABKeyID: "keyID",
				},
				wantErr: true,
			}
		},
		"fail/missing-eab-key-id": func(_ *testing.T) test {
			return test{
				fields: fields{
					EABMACKey: "29D7t6-mOuEV5vvBRX0UYF5T7x6fomidhM1kMJco-yw",
				},
				wantErr: true,
			}
		},
		"fail/invalid-mac-key": func(_ *testing.T) test {
			return test{
				fields: fields{
					EABMACKey: ">invalid-base64-url-encoded-mac-key<",
				},
				wantErr: true,
			}
		},
		"fail/trusted-ca-combined": func(t *testing.T) test {
			f, err := os.CreateTemp(t.TempDir(), "pomerium-test-ca")
			require.NoError(t, err)
			n, err := f.Write(certPEM)
			require.NoError(t, err)
			require.Equal(t, len(certPEM), n)
			return test{
				fields: fields{
					TrustedCA:     base64.StdEncoding.EncodeToString(certPEM),
					TrustedCAFile: f.Name(),
				},
				wantErr: true,
				cleanup: func() { os.Remove(f.Name()) },
			}
		},
		"fail/trusted-ca-invalid-base64-pem": func(_ *testing.T) test {
			return test{
				fields: fields{
					TrustedCA: ">invalid-base-64-data<",
				},
				wantErr: true,
			}
		},
		"fail/trusted-ca-missing-file": func(_ *testing.T) test {
			return test{
				fields: fields{
					TrustedCAFile: "some-non-existing-file",
				},
				wantErr: true,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			o := &AutocertOptions{
				Enable:        tc.fields.Enable,
				CA:            tc.fields.CA,
				Email:         tc.fields.Email,
				UseStaging:    tc.fields.UseStaging,
				EABKeyID:      tc.fields.EABKeyID,
				EABMACKey:     tc.fields.EABMACKey,
				MustStaple:    tc.fields.MustStaple,
				Folder:        tc.fields.Folder,
				TrustedCA:     tc.fields.TrustedCA,
				TrustedCAFile: tc.fields.TrustedCAFile,
			}
			if err := o.Validate(); (err != nil) != tc.wantErr {
				t.Errorf("AutocertOptions.Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.cleanup != nil {
				tc.cleanup()
			}
		})
	}
}
