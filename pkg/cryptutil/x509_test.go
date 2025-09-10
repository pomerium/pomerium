package cryptutil

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generated using:
//
//	openssl genpkey -algorithm x25519 -out priv.pem
//	openssl pkey -in priv.pem -out pub.pem -pubout
var (
	rawPrivateX25519Key = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIKALoNgzCksH0v0Bc7Ghl8vGin4MAIKpmtZSmaMN0Vtb
-----END PRIVATE KEY-----
`)
	rawPublicX25519Key = []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAk63g8PY1JJTkrranWTxGSd/yA5kAgJlPk4/srMKg9mg=
-----END PUBLIC KEY-----
`)
)

func TestPKCS8PrivateKey(t *testing.T) {
	block, _ := pem.Decode(rawPrivateX25519Key)

	kek, err := ParsePKCS8PrivateKey(block.Bytes)
	assert.NoError(t, err)
	assert.IsType(t, &PrivateKeyEncryptionKey{}, kek)

	t.Run("marshal", func(t *testing.T) {
		der, err := MarshalPKCS8PrivateKey(kek)
		require.NoError(t, err)
		actual := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		})
		assert.Equal(t, rawPrivateX25519Key, actual)
	})
}

func TestPKIXPublicKey(t *testing.T) {
	block, _ := pem.Decode(rawPublicX25519Key)

	kek, err := ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err)
	assert.IsType(t, &PublicKeyEncryptionKey{}, kek)

	t.Run("marshal", func(t *testing.T) {
		der, err := MarshalPKIXPublicKey(kek)
		require.NoError(t, err)
		actual := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		})
		assert.Equal(t, rawPublicX25519Key, actual)
	})
}

func TestFormatDistinguishedName(t *testing.T) {
	mustMarshal := func(v any) []byte {
		b, err := asn1.Marshal(v)
		require.NoError(t, err)
		return b
	}

	cases := []struct {
		input  []byte
		output string
		err    string
	}{
		{
			mustMarshal(pkix.RDNSequence{
				{{Type: oidCommonName, Value: "single name"}},
			}),
			"CN=single name",
			"",
		},
		{
			mustMarshal(pkix.RDNSequence{
				{{Type: oidOrganization, Value: "Pomerium, Inc."}},
				{{Type: oidOrganizationalUnit, Value: "Engineering"}},
				{{Type: oidOrganizationalUnit, Value: "Backend"}},
				{{Type: oidCommonName, Value: "John Doe"}},
			}),
			`O=Pomerium\, Inc.,OU=Engineering,OU=Backend,CN=John Doe`,
			"",
		},
		{
			mustMarshal(pkix.RDNSequence{
				{{Type: oidCountry, Value: "US"}},
				{{Type: oidOrganizationalUnit, Value: "Databases"}, {Type: oidOrganizationalUnit, Value: "Postgres"}},
				{{Type: oidCommonName, Value: "postgres"}},
			}),
			"C=US,OU=Postgres+OU=Databases,CN=postgres",
			"",
		},
		{
			mustMarshal(pkix.RDNSequence{
				{{Type: oidCountry, Value: "GB"}},
				{{Type: oidOrganization, Value: "Telecom"}},
				{{Type: oidOrganizationalUnit, Value: "Sales"}, {Type: oidLocality, Value: "Ipswich"}},
				{{Type: oidCommonName, Value: "Smith"}},
			}),
			"C=GB,O=Telecom,OU=Sales+L=Ipswich,CN=Smith",
			"",
		},
		{
			mustMarshal(pkix.RDNSequence{
				{{Type: oidUserPrincipalName, Value: "username"}}, // unknown name attribute type
			}),
			"1.3.6.1.4.1.311.20.2.3=#1308757365726e616d65",
			"",
		},
		{
			[]byte("\x30\x06\x80\x01\x09\x81\x01\x09"),
			"",
			"couldn't parse Distinguished Name: asn1: structure error: sequence tag mismatch",
		},
		{
			[]byte("0\x161\x140\x12\x06\x03U\x04\x03\x13\vsingle name+extra garbage on the end"),
			"",
			"unexpected data after name",
		},
	}
	for _, c := range cases {
		t.Run("", func(t *testing.T) {
			output, err := FormatDistinguishedName([]byte(c.input))
			if c.err != "" {
				require.ErrorContains(t, err, c.err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, c.output, output)
		})
	}
}

var (
	oidCountry            = []int{2, 5, 4, 6}
	oidOrganization       = []int{2, 5, 4, 10}
	oidOrganizationalUnit = []int{2, 5, 4, 11}
	oidCommonName         = []int{2, 5, 4, 3}
	oidSerialNumber       = []int{2, 5, 4, 5}
	oidLocality           = []int{2, 5, 4, 7}
	oidProvince           = []int{2, 5, 4, 8}
	oidStreetAddress      = []int{2, 5, 4, 9}
	oidPostalCode         = []int{2, 5, 4, 17}
	oidUserPrincipalName  = []int{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
)
