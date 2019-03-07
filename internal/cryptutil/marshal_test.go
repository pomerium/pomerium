package cryptutil

import (
	"bytes"
	"strings"
	"testing"
)

// A keypair for NIST P-256 / secp256r1
// Generated using:
//   openssl ecparam -genkey -name prime256v1 -outform PEM
var pemECPrivateKeyP256 = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOI+EZsjyN3jvWJI/KDihFmqTuDpUe/if6f/pgGTBta/oAoGCCqGSM49
AwEHoUQDQgAEhhObKJ1r1PcUw+3REd/TbmSZnDvXnFUSTwqQFo5gbfIlP+gvEYba
+Rxj2hhqjfzqxIleRK40IRyEi3fJM/8Qhg==
-----END EC PRIVATE KEY-----
`

var pemECPublicKeyP256 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhhObKJ1r1PcUw+3REd/TbmSZnDvX
nFUSTwqQFo5gbfIlP+gvEYba+Rxj2hhqjfzqxIleRK40IRyEi3fJM/8Qhg==
-----END PUBLIC KEY-----
`

var garbagePEM = `-----BEGIN GARBAGE-----
TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ=
-----END GARBAGE-----
`

func TestPublicKeyMarshaling(t *testing.T) {
	ecKey, err := DecodePublicKey([]byte(pemECPublicKeyP256))
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, _ := EncodePublicKey(ecKey)
	if !bytes.Equal(pemBytes, []byte(pemECPublicKeyP256)) {
		t.Fatal("public key encoding did not match")
	}

}

func TestPrivateKeyBadDecode(t *testing.T) {
	_, err := DecodePrivateKey([]byte(garbagePEM))
	if err == nil {
		t.Fatal("decoded garbage data without complaint")
	}
}

func TestPrivateKeyMarshaling(t *testing.T) {
	ecKey, err := DecodePrivateKey([]byte(pemECPrivateKeyP256))
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, _ := EncodePrivateKey(ecKey)
	if !strings.HasSuffix(pemECPrivateKeyP256, string(pemBytes)) {
		t.Fatal("private key encoding did not match")
	}
}

// Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.3.1
var jwtTest = []struct {
	sigBytes []byte
	b64sig   string
}{
	{
		sigBytes: []byte{14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21,
			88, 7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129, 154, 195, 22, 158,
			166, 101, 197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175,
			8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63, 127, 138, 131,
			163, 84, 213},
		b64sig: "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q",
	},
}

func TestJWTEncoding(t *testing.T) {
	for _, tt := range jwtTest {
		result := EncodeSignatureJWT(tt.sigBytes)

		if strings.Compare(result, tt.b64sig) != 0 {
			t.Fatalf("expected %s, got %s\n", tt.b64sig, result)
		}
	}
}

func TestJWTDecoding(t *testing.T) {
	for _, tt := range jwtTest {
		resultSig, err := DecodeSignatureJWT(tt.b64sig)
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(resultSig, tt.sigBytes) {
			t.Fatalf("decoded signature was incorrect")
		}
	}
}
