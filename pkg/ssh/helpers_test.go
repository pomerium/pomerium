package ssh_test

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

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
