package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDownstreamMTLSSettingsGetCA(t *testing.T) {
	t.Parallel()

	fakeCACert := []byte("--- FAKE CA CERT ---")
	caFile := filepath.Join(t.TempDir(), "CA.pem")
	os.WriteFile(caFile, fakeCACert, 0644)

	cases := []struct {
		label    string
		settings DownstreamMTLSSettings
		expected []byte
	}{
		{"not set", DownstreamMTLSSettings{}, nil},
		{"CA", DownstreamMTLSSettings{CA: "LS0tIEZBS0UgQ0EgQ0VSVCAtLS0="}, fakeCACert},
		{"CA file", DownstreamMTLSSettings{CAFile: caFile}, fakeCACert},
	}

	for i := range cases {
		c := &cases[i]
		t.Run(c.label, func(t *testing.T) {
			ca, err := c.settings.GetCA()
			require.NoError(t, err)
			assert.Equal(t, c.expected, ca)
		})
	}
}

func TestDownstreamMTLSSettingsGetCRL(t *testing.T) {
	t.Parallel()

	fakeCRL := []byte("--- FAKE CRL ---")
	crlFile := filepath.Join(t.TempDir(), "CRL.pem")
	os.WriteFile(crlFile, fakeCRL, 0644)

	cases := []struct {
		label    string
		settings DownstreamMTLSSettings
		expected []byte
	}{
		{"not set", DownstreamMTLSSettings{}, nil},
		{"CRL", DownstreamMTLSSettings{CRL: "LS0tIEZBS0UgQ1JMIC0tLQ=="}, fakeCRL},
		{"CRL file", DownstreamMTLSSettings{CRLFile: crlFile}, fakeCRL},
	}

	for i := range cases {
		c := &cases[i]
		t.Run(c.label, func(t *testing.T) {
			crl, err := c.settings.GetCRL()
			require.NoError(t, err)
			assert.Equal(t, c.expected, crl)
		})
	}
}

func TestDownstreamMTLSSettingsGetEnforcement(t *testing.T) {
	t.Parallel()

	cases := []struct {
		label    string
		settings DownstreamMTLSSettings
		expected MTLSEnforcement
	}{
		{"default",
			DownstreamMTLSSettings{}, MTLSEnforcementPolicyWithDefaultDeny,
		},
		{"policy",
			DownstreamMTLSSettings{Enforcement: "policy"}, MTLSEnforcementPolicy,
		},
		{"policy_with_default_deny",
			DownstreamMTLSSettings{Enforcement: "policy_with_default_deny"},
			MTLSEnforcementPolicyWithDefaultDeny,
		},
		{"reject_connection",
			DownstreamMTLSSettings{Enforcement: "reject_connection"},
			MTLSEnforcementRejectConnection,
		},
	}

	for i := range cases {
		c := &cases[i]
		t.Run(c.label, func(t *testing.T) {
			assert.Equal(t, c.expected, c.settings.GetEnforcement())
		})
	}
}

func TestDownstreamMTLSSettingsGetMaxVerifyDepth(t *testing.T) {
	t.Parallel()

	// MaxVerifyDepth should default to 1 if not set explicitly.
	var s DownstreamMTLSSettings
	assert.Equal(t, uint32(1), s.GetMaxVerifyDepth())

	var maxVerifyDepth uint32
	s.MaxVerifyDepth = &maxVerifyDepth
	assert.Equal(t, uint32(0), s.GetMaxVerifyDepth())

	maxVerifyDepth = 1
	assert.Equal(t, uint32(1), s.GetMaxVerifyDepth())

	maxVerifyDepth = 1000
	assert.Equal(t, uint32(1000), s.GetMaxVerifyDepth())
}

func TestDownstreamMTLSSettingsValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		label    string
		settings DownstreamMTLSSettings
		errorMsg string
	}{
		{"not set", DownstreamMTLSSettings{}, ""},
		{"both CA and CA file", DownstreamMTLSSettings{CA: "CA", CAFile: "CAFile"},
			"cannot set both ca and ca_file"},
		{"bad CA", DownstreamMTLSSettings{CA: "not%valid%base64%data"},
			"CA: illegal base64 data at input byte 3"},
		{"bad CA file", DownstreamMTLSSettings{CAFile: "-"},
			"CA file: open -: no such file or directory"},
		{"both CRL and CRL file", DownstreamMTLSSettings{CRL: "CRL", CRLFile: "CRLFile"},
			"cannot set both crl and crl_file"},
		{"bad CRL", DownstreamMTLSSettings{CRL: "dGhpc2lzZmluZQo="},
			"CRL: cryptutil: invalid crl, no X509 CRL block found"},
		{"bad CRL file", DownstreamMTLSSettings{CRLFile: "-"},
			"CRL file: open -: no such file or directory"},
		{"bad enforcement mode", DownstreamMTLSSettings{Enforcement: "whatever"},
			"unknown enforcement option"},
		{"OK", DownstreamMTLSSettings{
			CA:          "dGhpc2lzZmluZQo=",
			CRL:         "LS0tLS1CRUdJTiBYNTA5IENSTC0tLS0tCk1JSUNOVENCbmdJQkFUQU5CZ2txaGtpRzl3MEJBUXNGQURBNk1SNHdIQVlEVlFRS0V4VnRhMk5sY25RZ1pHVjIKWld4dmNHMWxiblFnUTBFeEdEQVdCZ05WQkFNVEQyUnZkMjV6ZEhKbFlXMGdRMEVnTWhjTk1qTXdOekU1TWpFMQpNREUxV2hjTk16TXdOekUyTWpFMU1ERTFXcUF3TUM0d0h3WURWUjBqQkJnd0ZvQVVDeFEyY0JhNVl6cVZ6YW1wCmlOQ3g4S3dGRnlRd0N3WURWUjBVQkFRQ0FoQUFNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJnUUNZYW14OHBNK1IKQ2x5c2tjdTdvdWh1L1IxSnkxbldHeVd0S3BoWXEwWEZiT0xsbmsyWjdlRGZBWDhFZWoyRmF2cXh6YXBSMngyTwo0aUpORENtaXdZWVlVUzJYMkxKM3JSUkpYeVh2V2h0ZkhyeFVSZDZCaXRDMklYcHlrQnRWbGYzekFuWjhHWkZRClMxamRmeUxNdUVBaUR3SWFpM1l0OEhzRHAvcUcwODlvWGNvU3R5UWcvdVJwbVd5MDVBOXVDVk9mTkhTTFNadTgKbHI0cWF0bGV1MHdXYlYxYW1MOHRPOXg0Q1JrTzBvMVlhUXE0RG9PcnVQciszTmtUbVB2R2lkaDNGNzFWNklFQQpoK0t6ZGJSWHhGbUNDV0xXbXBKRGNyZ1I3S1VxWk9oVVV0K0RVcWFxaFY0NHFJMG5ycFIrUVpMb2hvRG9yOUx3CksrdWZqM24yOWVTUlgrM1B4K29WV1BUOFlaUDJ1S1BkaXppOTZtZTJqV1RyNTF4OUFqRW9KRHNUbllSbDkrdVkKU2hpVXhXblRkUXNvb2tuSWZjUy8wemZnWjg3R3ZVVnppbkNRekpwd1Z4ZDRBbHQ4QWxSK2ZYQXFOSW9PZ3V5dgpwL0N0UlZualZFN2w3SFcvaFFScTFKMGlqQ0NLd215Zi9LVGQ2RUs0VGRydmJYL1U5bXNWTThZPQotLS0tLUVORCBYNTA5IENSTC0tLS0tCg==",
			Enforcement: "reject_connection",
		}, ""},
	}

	for i := range cases {
		c := &cases[i]
		t.Run(c.label, func(t *testing.T) {
			err := c.settings.validate()
			if c.errorMsg == "" {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, c.errorMsg, err.Error())
			}
		})
	}
}
