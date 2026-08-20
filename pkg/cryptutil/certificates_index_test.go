package cryptutil_test

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/derivecert"
)

func TestCertificatesIndex(t *testing.T) {
	t.Parallel()

	ca, err := derivecert.NewCA(cryptutil.NewKey())
	require.NoError(t, err)

	mkClientCert := func(domains []string) *x509.Certificate {
		pem, err := ca.NewServerCert(domains, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		})
		require.NoError(t, err)

		_, cert, err := pem.KeyCert()
		require.NoError(t, err)

		return cert
	}
	mkServerCert := func(domains []string) *x509.Certificate {
		pem, err := ca.NewServerCert(domains)
		require.NoError(t, err)

		_, cert, err := pem.KeyCert()
		require.NoError(t, err)

		return cert
	}

	testCases := []struct {
		names   []string
		test    string
		overlap bool
	}{
		{[]string{"aa.bb.cc", "cc.bb.aa"}, "aa.bb.c", false},
		{[]string{"aa.bb.cc"}, "aa.bb.cc", true},
		{[]string{"*.bb.cc"}, "aa.bb.cc", true},
		{[]string{"a1.bb.cc", "a2.bb.cc"}, "*.bb.cc", true},
		{[]string{"*.bb.cc", "a2.bb.cc"}, "*.bb.cc", true},
		{[]string{"*.aa.bb.cc"}, "*.bb.cc", false},
		{[]string{"*.aa.bb.cc"}, "aa.bb.cc", false},
		{[]string{"bb.cc"}, "*.bb.cc", false},
	}
	t.Run("match mix mode", func(t *testing.T) {
		for _, tc := range testCases {
			idx := cryptutil.NewCertificatesIndex()
			idx.Add(mkServerCert(tc.names))

			cert := mkServerCert([]string{tc.test})
			overlaps, _ := idx.OverlapsWithExistingCertificate(cert)
			assert.Equalf(t, tc.overlap, overlaps, "%v", tc)
		}
	})
	t.Run("different cert usages never match", func(t *testing.T) {
		for _, tc := range testCases {
			idx := cryptutil.NewCertificatesIndex()
			idx.Add(mkServerCert(tc.names))

			cert := mkClientCert([]string{tc.test})
			overlaps, _ := idx.OverlapsWithExistingCertificate(cert)
			assert.Equalf(t, false, overlaps, "%v", tc)
		}
	})
	t.Run("different cert usages should coexist in the index", func(t *testing.T) {
		for _, tc := range testCases {
			idx := cryptutil.NewCertificatesIndex()
			srv := mkServerCert(tc.names)
			client := mkClientCert(tc.names)
			idx.Add(srv)
			idx.Add(client)

			overlaps, _ := idx.OverlapsWithExistingCertificate(srv)
			assert.Equalf(t, true, overlaps, "%v", tc)

			overlaps, _ = idx.OverlapsWithExistingCertificate(client)
			assert.Equalf(t, true, overlaps, "%v", tc)
		}
	})
	t.Run("delete", func(t *testing.T) {
		for _, tc := range testCases {
			idx := cryptutil.NewCertificatesIndex()
			srv := mkServerCert(tc.names)
			client := mkClientCert(tc.names)
			idx.Add(srv)
			idx.Add(client)

			idx.Delete(srv)
			overlaps, _ := idx.OverlapsWithExistingCertificate(srv)
			assert.Equalf(t, false, overlaps, "%v", tc)

			overlaps, _ = idx.OverlapsWithExistingCertificate(client)
			assert.Equalf(t, true, overlaps, "%v", tc)
		}
	})
}
