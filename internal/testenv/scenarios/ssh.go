package scenarios

import (
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/pkg/slices"
)

type SSHConfig struct {
	// SSH listener address. Defaults to ":2200" if not set.
	Addr string

	Hostname string

	// Host key(s). An Ed25519 key will be generated if not set.
	// Elements must be of a type supported by [ssh.NewSignerFromKey].
	HostKeys []any

	// User CA key, for signing SSH certificates used to authenticate to an
	// upstream. An Ed25519 key will be generated if not set.
	// Must be a type supported by [ssh.NewSignerFromKey].
	UserCAKey any
}

func SSH(c SSHConfig) testenv.Modifier {
	return testenv.ModifierFunc(func(ctx context.Context, cfg *config.Config) {
		env := testenv.EnvFromContext(ctx)

		// Apply defaults.
		if c.Addr == "" {
			c.Addr = ":2200"
		}
		if len(c.HostKeys) == 0 {
			c.HostKeys = []any{newEd25519Key(env)}
		}
		if c.Hostname == "" {
			// XXX: is there a reasonable default for this?
		}
		if c.UserCAKey == nil {
			c.UserCAKey = newEd25519Key(env)
		}

		// Update configuration.
		cfg.Options.SSHAddr = c.Addr
		cfg.Options.SSHHostname = c.Hostname
		cfg.Options.SSHHostKeys = slices.Map(c.HostKeys, func(key any) config.SSHKeyPair {
			return writeSSHKeyPair(env, key)
		})
		cfg.Options.SSHUserCAKey = writeSSHKeyPair(env, c.UserCAKey)
	})
}

func newEd25519Key(env testenv.Environment) ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(nil)
	env.Require().NoError(err)
	return priv
}

// writeSSHKeyPair takes a private key and writes SSH private and public key
// files to the test env temp directory, returning a [config.SSHKeyPair] with
// the written filenames. The key must be of a type supported by the
// [ssh.NewSignerFromKey] method.
func writeSSHKeyPair(env testenv.Environment, key any) config.SSHKeyPair {
	signer, err := ssh.NewSignerFromKey(key)
	pub := signer.PublicKey()
	env.Require().NoError(err)

	dir := env.TempDir()
	basename := fmt.Sprintf("ssh-key-%d", rand.Int())
	privname := filepath.Join(dir, basename)
	pubname := privname + ".pub"

	// marshal and write private key to disk
	pemBlock, err := ssh.MarshalPrivateKey(key, "")
	env.Require().NoError(err)
	privkeyContents := pem.EncodeToMemory(pemBlock)
	err = os.WriteFile(privname, privkeyContents, 0o600)
	env.Require().NoError(err)

	// marshal and write public key to disk
	pubkeyContents := ssh.MarshalAuthorizedKey(pub)
	err = os.WriteFile(pubname, pubkeyContents, 0o600)
	env.Require().NoError(err)

	return config.SSHKeyPair{
		PublicKeyFile:  pubname,
		PrivateKeyFile: privname,
	}
}
