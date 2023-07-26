package cryptutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCertificateServerNames(t *testing.T) {
	cert, err := GenerateCertificate(nil, "www.example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"www.example.com"}, GetCertificateServerNames(cert))
}
