package criteria

import (
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

const testCert = `
-----BEGIN CERTIFICATE-----
MIIBYTCCAQigAwIBAgICEAEwCgYIKoZIzj0EAwIwGjEYMBYGA1UEAxMPVHJ1c3Rl
ZCBSb290IENBMCAYDzAwMDEwMTAxMDAwMDAwWhcNMzMwNzMxMTUzMzE5WjAeMRww
GgYDVQQDExN0cnVzdGVkIGNsaWVudCBjZXJ0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEfAYP3ZwiKJgk9zXpR/CMHYlAxjweJaMJihIS2FTA5gb0xBcTEe5AGpNF
CHWPk4YCB25VeHg9GmY9Q1+qDD1hdqM4MDYwEwYDVR0lBAwwCgYIKwYBBQUHAwIw
HwYDVR0jBBgwFoAUXep6D8FTP6+5ZdR/HjP3pYfmxkwwCgYIKoZIzj0EAwIDRwAw
RAIgProROtxpvKS/qjrjonSvacnhdU0JwoXj2DgYvF/qjrUCIAXlHkdEzyXmTLuu
/YxuOibV35vlaIzj21GRj4pYmVR1
-----END CERTIFICATE-----`

// testCertWithSANs is a certificate with 6 Subject Alternative Names:
// DNS:1.example.com, DNS:2.example.com, email:email-1@example.com,
// email:email-2@example.com, URI:https://example.com/uri-1, and
// URI:https://example.com/uri-2.
const testCertWithSANs = `
-----BEGIN CERTIFICATE-----
MIIB9TCCAZugAwIBAgIDAIABMAoGCCqGSM49BAMCMBoxGDAWBgNVBAMTD1RydXN0
ZWQgUm9vdCBDQTAeFw0yNDAxMjIyMzU1NTNaFw0zNDAxMTkyMzU1NTNaMCUxIzAh
BgNVBAMTGmNsaWVudCBjZXJ0IHdpdGggbWFueSBTQU5zMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEJNVizgh7I/609xD6Dik7QrIzwSp6zIgSeKEfekic7r3rd8fC
0W84UORBjFXxRa4nxj8tyanN4PreD1veACPjHqOBxDCBwTATBgNVHSUEDDAKBggr
BgEFBQcDAjAfBgNVHSMEGDAWgBQ1yn6j/DJdpmqyNIV8/lJBYsIuyzCBiAYDVR0R
BIGAMH6CDTEuZXhhbXBsZS5jb22CDTIuZXhhbXBsZS5jb22BE2VtYWlsLTFAZXhh
bXBsZS5jb22BE2VtYWlsLTJAZXhhbXBsZS5jb22GGWh0dHBzOi8vZXhhbXBsZS5j
b20vdXJpLTGGGWh0dHBzOi8vZXhhbXBsZS5jb20vdXJpLTIwCgYIKoZIzj0EAwID
SAAwRQIgKqRs9N3EOmzW2ZPQgJh2un6XaQbXtyE9O9TZEQGFr2gCIQCC16tr754m
z60udX689FtwwnWYmteZsZstBoEbPSTzWw==
-----END CERTIFICATE-----`

func TestClientCertificate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		label    string
		policy   string
		cert     string
		expected A
	}{
		{
			"no certificate",
			`allow:
  or:
    - client_certificate:
        fingerprint: 17859273e8a980631d367b2d5a6a6635412b0f22835f69e47b3f65624546a704`,
			"",
			A{false, A{ReasonClientCertificateUnauthorized}, M{}},
		},
		{
			"no fingerprint match",
			`allow:
  or:
    - client_certificate:
        fingerprint: df6ff72fe9116521268f6f2dd4966f51df479883fe7037b39f75916ac3049d1a`,
			testCert,
			A{false, A{ReasonClientCertificateUnauthorized}, M{}},
		},
		{
			"fingerprint match",
			`allow:
  or:
    - client_certificate:
        fingerprint: 17859273e8a980631d367b2d5a6a6635412b0f22835f69e47b3f65624546a704`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{
			"fingerprint list match",
			`allow:
  or:
    - client_certificate:
        fingerprint:
          - 17859273e8a980631d367b2d5a6a6635412b0f22835f69e47b3f65624546a704
          - df6ff72fe9116521268f6f2dd4966f51df479883fe7037b39f75916ac3049d1a`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{
			"spki hash match",
			`allow:
  or:
    - client_certificate:
        spki_hash: FsDbM0rUYIiL3V339eIKqiz6HPSB+Pz2WeAWhqlqh8U=`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{
			"spki hash list match",
			`allow:
  or:
    - client_certificate:
        spki_hash:
          - FsDbM0rUYIiL3V339eIKqiz6HPSB+Pz2WeAWhqlqh8U=
          - NvqYIYSbgK2vCJpQhObf77vv+bQWtc5ek5RIOwPiC9A=`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{
			"no email match",
			`allow:
  or:
    - client_certificate:
        san_email:
          is: not-present@example.com`,
			testCertWithSANs,
			A{false, A{ReasonClientCertificateUnauthorized}, M{}},
		},
		{
			"email match",
			`allow:
  or:
    - client_certificate:
        san_email:
          is: email-1@example.com`,
			testCertWithSANs,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{
			"no dns match",
			`allow:
  or:
    - client_certificate:
        san_dns:
          is: not-present.example.com`,
			testCertWithSANs,
			A{false, A{ReasonClientCertificateUnauthorized}, M{}},
		},
		{
			"dns match",
			`allow:
  or:
    - client_certificate:
        san_dns:
          is: 1.example.com`,
			testCertWithSANs,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{
			"no uri match",
			`allow:
  or:
    - client_certificate:
        san_uri:
          is: https://example.com/not-present`,
			testCertWithSANs,
			A{false, A{ReasonClientCertificateUnauthorized}, M{}},
		},
		{
			"uri match",
			`allow:
  or:
    - client_certificate:
        san_uri:
          is: 'https://example.com/uri-1'`,
			testCertWithSANs,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
	}

	for i := range cases {
		c := cases[i]
		t.Run(c.label, func(t *testing.T) {
			t.Parallel()

			input := Input{
				HTTP: InputHTTP{
					ClientCertificate: ClientCertificateInfo{
						Leaf: c.cert,
					},
				},
			}
			res, err := evaluate(t, c.policy, nil, input)
			require.NoError(t, err)
			assert.Equal(t, c.expected, res["allow"])
		})
	}
}

func TestCanonicalCertFingerprint(t *testing.T) {
	t.Parallel()

	cases := []struct {
		label  string
		input  string
		output string
		err    string
	}{
		{
			"object",
			`{}`, "", "certificate fingerprint must be a string (was {})",
		},
		{
			"empty",
			`""`, "", "certificate fingerprint must not be empty",
		},
		{
			"SHA-1 fingerprint",
			`"B1:E6:A2:DC:DD:6B:87:A4:9B:C5:7C:3B:7C:7F:1C:74:9A:DB:88:36"`,
			"", "unsupported certificate fingerprint format (B1:E6:A2:DC:DD:6B:87:A4:9B:C5:7C:3B:7C:7F:1C:74:9A:DB:88:36)",
		},
		{
			"uppercase short",
			`"DF6FF72FE9116521268F6F2DD4966F51DF479883FE7037B39F75916AC3049D1A"`,
			"", "unsupported certificate fingerprint format (DF6FF72FE9116521268F6F2DD4966F51DF479883FE7037B39F75916AC3049D1A)",
		},
		{
			"valid short",
			`"df6ff72fe9116521268f6f2dd4966f51df479883fe7037b39f75916ac3049d1a"`,
			"df6ff72fe9116521268f6f2dd4966f51df479883fe7037b39f75916ac3049d1a", "",
		},
		{
			"lowercase long",
			`"df:6f:f7:2f:e9:11:65:21:26:8f:6f:2d:d4:96:6f:51:df:47:98:83:fe:70:37:b3:9f:75:91:6a:c3:04:9d:1a"`,
			"", "unsupported certificate fingerprint format (df:6f:f7:2f:e9:11:65:21:26:8f:6f:2d:d4:96:6f:51:df:47:98:83:fe:70:37:b3:9f:75:91:6a:c3:04:9d:1a)",
		},
		{
			"valid long",
			`"DF:6F:F7:2F:E9:11:65:21:26:8F:6F:2D:D4:96:6F:51:DF:47:98:83:FE:70:37:B3:9F:75:91:6A:C3:04:9D:1A"`,
			"df6ff72fe9116521268f6f2dd4966f51df479883fe7037b39f75916ac3049d1a", "",
		},
	}

	for i := range cases {
		c := cases[i]
		t.Run(c.label, func(t *testing.T) {
			t.Parallel()

			value, err := parser.ParseValue(strings.NewReader(c.input))
			require.NoError(t, err)

			f, err := canonicalCertFingerprint(value)
			if c.err == "" {
				require.NoError(t, err)
				assert.Equal(t, ast.String(c.output), f)
			} else {
				assert.Equal(t, c.err, err.Error())
			}
		})
	}
}

func TestSPKIHashFormatErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		label string
		input string
		err   string
	}{
		{
			"object",
			`{}`, "certificate SPKI hash condition expects a string or array of strings",
		},
		{
			"not base64",
			`"not%valid%base64%data"`, "certificate SPKI hash must be a base64-encoded SHA-256 hash (was not%valid%base64%data)",
		},
		{
			"SHA-1 hash",
			`"VYby3BAoHawLLtsyckwo5Q=="`, "certificate SPKI hash must be a base64-encoded SHA-256 hash (was VYby3BAoHawLLtsyckwo5Q==)",
		},
		{
			"valid",
			`"FsDbM0rUYIiL3V339eIKqiz6HPSB+Pz2WeAWhqlqh8U="`, "",
		},
	}

	for i := range cases {
		c := cases[i]
		t.Run(c.label, func(t *testing.T) {
			t.Parallel()

			value, err := parser.ParseValue(strings.NewReader(c.input))
			require.NoError(t, err)

			var body ast.Body
			err = addCertSPKIHashCondition(&body, value)
			if c.err == "" {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, c.err, err.Error())
			}
		})
	}
}
