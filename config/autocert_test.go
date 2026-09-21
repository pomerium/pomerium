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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
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
		fields           fields
		wantErr          bool
		useTrustedCAFile bool
	}
	tests := map[string]test{
		"ok/custom-ca": {
			fields: fields{
				CA: "test-ca.example.com/directory",
			},
			wantErr: false,
		},
		"ok/eab": {
			fields: fields{
				EABKeyID:  "keyID",
				EABMACKey: "29D7t6-mOuEV5vvBRX0UYF5T7x6fomidhM1kMJco-yw",
			},
			wantErr: false,
		},
		"ok/trusted-ca": {
			fields: fields{
				TrustedCA: base64.StdEncoding.EncodeToString(certPEM),
			},
			wantErr: false,
		},
		"ok/trusted-ca-file": {
			wantErr:          false,
			useTrustedCAFile: true,
		},
		"fail/missing-eab-key": {
			fields: fields{
				EABKeyID: "keyID",
			},
			wantErr: true,
		},
		"fail/missing-eab-key-id": {
			fields: fields{
				EABMACKey: "29D7t6-mOuEV5vvBRX0UYF5T7x6fomidhM1kMJco-yw",
			},
			wantErr: true,
		},
		"fail/invalid-mac-key": {
			fields: fields{
				EABMACKey: ">invalid-base64-url-encoded-mac-key<",
			},
			wantErr: true,
		},
		"fail/trusted-ca-combined": {
			fields: fields{
				TrustedCA: base64.StdEncoding.EncodeToString(certPEM),
			},
			wantErr:          true,
			useTrustedCAFile: true,
		},
		"fail/trusted-ca-invalid-base64-pem": {
			fields: fields{
				TrustedCA: ">invalid-base-64-data<",
			},
			wantErr: true,
		},
		"fail/trusted-ca-missing-file": {
			fields: fields{
				TrustedCAFile: "some-non-existing-file",
			},
			wantErr: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			trustedCAFile := tc.fields.TrustedCAFile
			if tc.useTrustedCAFile {
				trustedCAFile = testutil.WriteFile(t, "pomerium-test-ca", certPEM)
			}
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
				TrustedCAFile: trustedCAFile,
			}
			if err := o.Validate(); (err != nil) != tc.wantErr {
				t.Errorf("AutocertOptions.Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
