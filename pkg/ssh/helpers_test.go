package ssh_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

type SSHKeys struct {
	// These keys are deterministically generated

	// ClientKey SSH client private key for authentication
	ClientKey ed25519.PrivateKey
	// ServerHostKey key for server identification
	ServerHostKey ed25519.PrivateKey
	// UpstreamHostKey for upstream identification
	UpstreamHostKey ed25519.PrivateKey
	// UserCAKey Certificate Authority key for signing user certificates
	UserCAKey ed25519.PrivateKey
	// ClientCAKey Certificate Authority key for signing client certificates
	ClientCAKey ed25519.PrivateKey

	// These keys are non-deterministically generated

	// ClientCASshPubKey Client CA public key in SSH wire format
	ClientCASshPubKey gossh.PublicKey
	// ClientSSHPubKey Client public key in SSH wire format
	ClientSSHPubKey gossh.PublicKey
}

func NewSSHKeys(t *testing.T) SSHKeys {
	t.Helper()

	s := SSHKeys{}
	s.ClientKey = newSSHKey(t)
	s.ServerHostKey = newSSHKey(t)

	s.UpstreamHostKey = newSSHKey(t)
	s.UserCAKey = newSSHKey(t)
	s.ClientCAKey = newSSHKey(t)

	var err error
	s.ClientSSHPubKey, err = gossh.NewPublicKey(s.ClientKey.Public())
	require.NoError(t, err)
	s.ClientCASshPubKey, err = gossh.NewPublicKey(s.ClientCAKey.Public())
	require.NoError(t, err)
	return s
}

// newSSHKey generates a new Ed25519 ssh key.
func newSSHKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return priv
}

// newSignerFromKey is a wrapper around ssh.NewSignerFromKey that will fail on error.
func newSignerFromKey(t *testing.T, key any) gossh.Signer {
	t.Helper()
	signer, err := gossh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

// newPublicKey is a wrapper around ssh.NewPublicKey that will fail on error.
func newPublicKey(t *testing.T, key any) gossh.PublicKey {
	t.Helper()
	sshkey, err := gossh.NewPublicKey(key)
	require.NoError(t, err)
	return sshkey
}

func VerifyWorkingShell(t *testing.T, client *gossh.Client) {
	t.Helper()
	sess, err := client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	var b bytes.Buffer
	sess.Stdout = &b
	sess.Stdin = strings.NewReader("hello world\r")
	require.NoError(t, sess.Shell())
	require.NoError(t, sess.Wait())

	assert.Equal(t, "> hello world\r\nhello world\r\n> ", b.String())
}

func RawFingerprintSHA256(pk gossh.PublicKey) []byte {
	// equivalent to sshkey_fingerprint_raw(), which only uses the plain key
	switch pk := pk.(type) {
	case *gossh.Certificate:
		return RawFingerprintSHA256(pk.Key)
	default:
		return (*new(sha256.Sum256(pk.Marshal())))[:]
	}
}

func TestRawFingerprintSHA256(t *testing.T) {
	clientCAKey := newSSHKey(t)
	sshKey := newSignerFromKey(t, newSSHKey(t))

	caSigner, err := gossh.NewSignerFromKey(clientCAKey)
	require.NoError(t, err)
	cert := &gossh.Certificate{
		CertType:    gossh.UserCert,
		Key:         sshKey.PublicKey(),
		ValidAfter:  uint64(time.Now().Add(-1 * time.Minute).Unix()),
		ValidBefore: uint64(time.Now().Add(1 * time.Hour).Unix()),
	}
	cert.SignCert(rand.Reader, caSigner)

	certKey, err := gossh.NewCertSigner(cert, sshKey)
	require.NoError(t, err)

	// The public key fingerprints sent by envoy use the plain key. If the key
	// is a certificate key, its fingerprint is always identical to the non-cert
	// version of that key. [gossh.FingerprintSHA256] does not do this however,
	// and certificate key fingerprints will be different.
	// Use these functions instead in tests to generate fingerprints that will
	// match the ones from envoy. This isn't needed outside of tests because
	// envoy sends the fingerprint along with the public key so that we don't
	// have to re-compute it (with an implementation that may not be identical).

	// sanity check
	require.NotEqual(t, gossh.FingerprintSHA256(sshKey.PublicKey()), gossh.FingerprintSHA256(certKey.PublicKey()))

	assert.Equal(t, RawFingerprintSHA256(sshKey.PublicKey()), RawFingerprintSHA256(certKey.PublicKey()))
}

func FormatRawFingerprint(rawFp []byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(rawFp)
}

func SessionBindingIDFromPublicKey(pk gossh.PublicKey) string {
	return "sshkey-" + FormatRawFingerprint(RawFingerprintSHA256(pk))
}
