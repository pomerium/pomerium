package cryptutil_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestNormalizePEM(t *testing.T) {
	t.Parallel()

	rootCA, intermediateCA, cert := testutil.GenerateCertificateChain(t)

	for _, tc := range []struct {
		input  []byte
		expect []byte
	}{
		{
			input:  slices.Concat(rootCA.PublicPEM, intermediateCA.PublicPEM, cert.PublicPEM, cert.PrivateKeyPEM),
			expect: slices.Concat(cert.PublicPEM, cert.PrivateKeyPEM, intermediateCA.PublicPEM, rootCA.PublicPEM),
		},
		{
			// make sure we handle a file without a trailing newline
			input:  slices.Concat(intermediateCA.PublicPEM, bytes.TrimRight(cert.PublicPEM, "\n")),
			expect: slices.Concat(cert.PublicPEM, intermediateCA.PublicPEM),
		},
		{
			input:  slices.Concat(cert.PublicPEM, cert.PrivateKeyPEM, intermediateCA.PublicPEM, rootCA.PublicPEM),
			expect: slices.Concat(cert.PublicPEM, cert.PrivateKeyPEM, intermediateCA.PublicPEM, rootCA.PublicPEM),
		},
		{
			input:  nil,
			expect: nil,
		},
		{
			input:  []byte("\n\n\nNON PEM DATA\n\n\n"),
			expect: []byte("\n\n\nNON PEM DATA\n\n\n"),
		},
		{
			input:  rootCA.PublicPEM,
			expect: rootCA.PublicPEM,
		},
		{
			input:  slices.Concat(rootCA.PublicPEM, intermediateCA.PublicPEM, cert.PublicPEM, cert.PrivateKeyPEM),
			expect: slices.Concat(cert.PublicPEM, cert.PrivateKeyPEM, intermediateCA.PublicPEM, rootCA.PublicPEM),
		},
		{
			// looks a bit weird, but the text before a block gets moved with it
			input:  slices.Concat([]byte("BEFORE\n"), intermediateCA.PublicPEM, []byte("BETWEEN\n"), cert.PublicPEM, []byte("AFTER\n")),
			expect: slices.Concat([]byte("BETWEEN\n"), cert.PublicPEM, []byte("AFTER\n"), []byte("BEFORE\n"), intermediateCA.PublicPEM),
		},
	} {
		actual := cryptutil.NormalizePEM(tc.input)
		assert.Equal(t, string(tc.expect), string(actual))
	}
}
