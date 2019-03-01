package cryptutil

import (
	"testing"
)

func TestES256Signer(t *testing.T) {
	signer, err := NewES256Signer([]byte(pemECPrivateKeyP256), "destination-url")
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		t.Fatal("signer should not be nil")
	}
	rawJwt, err := signer.SignJWT("joe-user", "joe-user@example.com", "group1,group2")
	if err != nil {
		t.Fatal(err)
	}
	if rawJwt == "" {
		t.Fatal("jwt should not be nil")
	}
}

func TestNewES256Signer(t *testing.T) {

	tests := []struct {
		name     string
		privKey  []byte
		audience string
		wantErr  bool
	}{
		{"working example", []byte(pemECPrivateKeyP256), "some-domain.com", false},
		{"bad private key", []byte(garbagePEM), "some-domain.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewES256Signer(tt.privKey, tt.audience)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewES256Signer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
