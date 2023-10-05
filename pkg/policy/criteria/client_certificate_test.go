package criteria

import (
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

const testCert = `
-----BEGIN CERTIFICATE-----
MIICPzCCAeWgAwIBAgIQYAOF5EYVQhvchRr58fDzaTAKBggqhkjOPQQDAjAaMRgw
FgYDVQQDEw9UcnVzdGVkIFJvb3QgQ0EwHhcNMjMxMDA1MTM0MTQ2WhcNMzMxMDAy
MTM0MTQ1WjAeMRwwGgYDVQQDExN0cnVzdGVkIGNsaWVudCBjZXJ0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEWGaY+S59zsNG/b1B18m68jZVWL5zaVAm0DQPYez4
fcnRO9JsHDK7mHYgI9dlcO58u8NCvBXp6BfRXG0oj+Rc7qOCAQcwggEDMA4GA1Ud
DwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0O
BBYEFNfMFyRLWjw2B1z0Ri45D+/pJORjMB8GA1UdIwQYMBaAFLXqXh23FkH/ZX5i
Wg2pR+8DoZjfMIGRBgNVHREEgYkwgYaCHXN1cGVyc2VjcmV0c2VydmVyLmV4YW1w
bGUuY29tgRBqb2huQGV4YW1wbGUuY29tgRByb290QGV4YW1wbGUuY29thwSsEAAF
hiNzcGlmZmU6Ly9leGFtcGxlLmNvbS9teXNlcnZpY2Uvam9oboYWaHR0cHM6Ly9v
dGhlcndvcmxkLmNvbTAKBggqhkjOPQQDAgNIADBFAiB9l/UxylEWgTuug7CsY1WF
Mfqj2RlAA7gUb1oRLoJENwIhALlcKIgOOHhg9TTGmrCsfvotZSOQe798zB/+4ZHb
LYc+
-----END CERTIFICATE-----`

func TestClientCertificate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		label    string
		policy   string
		cert     string
		expected A
	}{
		{"no certificate",
			`allow:
  or:
    - client_certificate:
        fingerprint: f31b6b73e8d089a69f8ad972fec59e638f42c3c0488fc650323bf85dd593cdef`,
			"",
			A{false, A{ReasonClientCertificateUnauthorized}, M{}},
		},
		{"no fingerprint match",
			`allow:
  or:
    - client_certificate:
        fingerprint: df6ff72fe9116521268f6f2dd4966f51df479883fe7037b39f75916ac3049d1a`,
			testCert,
			A{false, A{ReasonClientCertificateUnauthorized}, M{}},
		},
		{"fingerprint match",
			`allow:
  or:
    - client_certificate:
        fingerprint: f31b6b73e8d089a69f8ad972fec59e638f42c3c0488fc650323bf85dd593cdef`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{"fingerprint list match",
			`allow:
  or:
    - client_certificate:
        fingerprint:
          - f31b6b73e8d089a69f8ad972fec59e638f42c3c0488fc650323bf85dd593cdef
          - df6ff72fe9116521268f6f2dd4966f51df479883fe7037b39f75916ac3049d1a`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{"spki hash match",
			`allow:
  or:
    - client_certificate:
        spki_hash: byYc5v1pf/sb3u77NDp1Jq/QQXuzT39Uk3W2IlYXXBI=`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{"spki hash list match",
			`allow:
  or:
    - client_certificate:
        spki_hash:
          - byYc5v1pf/sb3u77NDp1Jq/QQXuzT39Uk3W2IlYXXBI=
          - NvqYIYSbgK2vCJpQhObf77vv+bQWtc5ek5RIOwPiC9A=`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{"no email match",
			`allow:
  or:
    - client_certificate:
        email:
          - nothere@example.com`,
			testCert,
			A{false, A{ReasonClientCertificateUnauthorized}, M{}},
		},
		{"email match single line",
			`allow:
  or:
    - client_certificate:
        email: root@example.com`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{"email match",
			`allow:
  or:
    - client_certificate:
        email:
          - john@example.com`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{"no dns match",
			`allow:
  or:
    - client_certificate:
        dns:
          - invalid.match.com`,
			testCert,
			A{false, A{ReasonClientCertificateUnauthorized}, M{}},
		},
		{"dns match single line",
			`allow:
  or:
    - client_certificate:
        dns: supersecretserver.example.com`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{"dns match",
			`allow:
  or:
    - client_certificate:
        dns:
          - supersecretserver.example.com`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{"no uri match",
			`allow:
  or:
    - client_certificate:
        uri:
          - http://dummy`,
			testCert,
			A{false, A{ReasonClientCertificateUnauthorized}, M{}},
		},
		{"uri match single line",
			`allow:
  or:
    - client_certificate:
        uri: spiffe://example.com/myservice/john`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{"uri match",
			`allow:
  or:
    - client_certificate:
        uri:
          - spiffe://example.com/myservice/john`,
			testCert,
			A{true, A{ReasonClientCertificateOK}, M{}},
		},
		{"ensure uri match consistency",
			`allow:
  or:
    - client_certificate:
        uri:
          - spiffe://otherworld.com`,
			testCert,
			A{false, A{ReasonClientCertificateUnauthorized}, M{}},
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
		{"object",
			`{}`, "", "certificate fingerprint must be a string (was {})",
		},
		{"empty",
			`""`, "", "certificate fingerprint must not be empty",
		},
		{"SHA-1 fingerprint",
			`"B1:E6:A2:DC:DD:6B:87:A4:9B:C5:7C:3B:7C:7F:1C:74:9A:DB:88:36"`,
			"", "unsupported certificate fingerprint format (B1:E6:A2:DC:DD:6B:87:A4:9B:C5:7C:3B:7C:7F:1C:74:9A:DB:88:36)",
		},
		{"uppercase short",
			`"DF6FF72FE9116521268F6F2DD4966F51DF479883FE7037B39F75916AC3049D1A"`,
			"", "unsupported certificate fingerprint format (DF6FF72FE9116521268F6F2DD4966F51DF479883FE7037B39F75916AC3049D1A)",
		},
		{"valid short",
			`"df6ff72fe9116521268f6f2dd4966f51df479883fe7037b39f75916ac3049d1a"`,
			"df6ff72fe9116521268f6f2dd4966f51df479883fe7037b39f75916ac3049d1a", "",
		},
		{"lowercase long",
			`"df:6f:f7:2f:e9:11:65:21:26:8f:6f:2d:d4:96:6f:51:df:47:98:83:fe:70:37:b3:9f:75:91:6a:c3:04:9d:1a"`,
			"", "unsupported certificate fingerprint format (df:6f:f7:2f:e9:11:65:21:26:8f:6f:2d:d4:96:6f:51:df:47:98:83:fe:70:37:b3:9f:75:91:6a:c3:04:9d:1a)",
		},
		{"valid long",
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
		{"object",
			`{}`, "certificate SPKI hash condition expects a string or array of strings",
		},
		{"not base64",
			`"not%valid%base64%data"`, "certificate SPKI hash must be a base64-encoded SHA-256 hash (was not%valid%base64%data)",
		},
		{"SHA-1 hash",
			`"VYby3BAoHawLLtsyckwo5Q=="`, "certificate SPKI hash must be a base64-encoded SHA-256 hash (was VYby3BAoHawLLtsyckwo5Q==)",
		},
		{"valid",
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

func TestEmailFormatErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		label string
		input string
		err   string
	}{
		{"object",
			`{}`, "certificate SAN email condition expects a string or array of strings",
		},
		{"not valid email",
			`"not-an-email"`, "certificate SAN email must be a valid email address (was not-an-email)",
		},
		{"not valid email",
			`"@example.com"`, "certificate SAN email must be a valid email address (was @example.com)",
		},
		{"valid",
			`"test@example.com"`, "",
		},
	}

	for i := range cases {
		c := cases[i]
		t.Run(c.label, func(t *testing.T) {
			t.Parallel()

			value, err := parser.ParseValue(strings.NewReader(c.input))
			require.NoError(t, err)

			var body ast.Body
			err = addSanEmailCondition(&body, value)
			if c.err == "" {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, c.err, err.Error())
			}
		})
	}
}


func TestDNSFormatErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		label string
		input string
		err   string
	}{
		{"object",
			`{}`, "certificate SAN dns condition expects a string or array of strings",
		},
		{"not valid dns",
			`"-not-a-domain"`, "certificate SAN dns must be a valid DNS name (was -not-a-domain)",
		},
		{"not valid dns",
			`"@example.com"`, "certificate SAN dns must be a valid DNS name (was @example.com)",
		},
		{"valid",
			`"www.example.com"`, "",
		},
	}

	for i := range cases {
		c := cases[i]
		t.Run(c.label, func(t *testing.T) {
			t.Parallel()

			value, err := parser.ParseValue(strings.NewReader(c.input))
			require.NoError(t, err)

			var body ast.Body
			err = addSanDNSCondition(&body, value)
			if c.err == "" {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, c.err, err.Error())
			}
		})
	}
}


func TestIPFormatErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		label string
		input string
		err   string
	}{
		{"object",
			`{}`, "certificate SAN IP condition expects a string or array of strings",
		},
		{"not valid ip",
			`"-not-an-ip"`, "certificate SAN IP must be a valid IP address (was -not-an-ip)",
		},
		{"not valid ip 2",
			`"@example.com"`, "certificate SAN IP must be a valid IP address (was @example.com)",
		},
		{"not valid ip 3",
			`"10.10.10.10.2"`, "certificate SAN IP must be a valid IP address (was 10.10.10.10.2)",
		},
		{"not valid ipv6",
			`"2001:0db8:85a3::8a2e:037j"`, "certificate SAN IP must be a valid IP address (was 2001:0db8:85a3::8a2e:037j)",
		},
		{"valid",
			`"172.16.0.1"`, "",
		},
		{"valid IPv6",
			`"2001:0db8:85a3:0000:0000:8a2e:0370:7334"`, "",
		},
	}

	for i := range cases {
		c := cases[i]
		t.Run(c.label, func(t *testing.T) {
			t.Parallel()

			value, err := parser.ParseValue(strings.NewReader(c.input))
			require.NoError(t, err)

			var body ast.Body
			err = addSanIPCondition(&body, value)
			if c.err == "" {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, c.err, err.Error())
			}
		})
	}
}
