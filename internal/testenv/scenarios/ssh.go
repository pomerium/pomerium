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

		if len(c.HostKeys) == 0 {
			c.HostKeys = []any{newEd25519Key(env)}
		}

		if c.UserCAKey == nil {
			c.UserCAKey = newEd25519Key(env)
		}

		cfg.Options.SSHHostKeys = slices.Map(c.HostKeys, func(key any) string {
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
func writeSSHKeyPair(env testenv.Environment, key any) string {
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

	return privname
}

// EmptyKeyboardInteractiveChallenge responds to any keyboard-interactive
// challenges with zero prompts, and fails otherwise.
type EmptyKeyboardInteractiveChallenge struct {
	testenv.DefaultAttach
}

func (c *EmptyKeyboardInteractiveChallenge) Do(
	name, instruction string, questions []string, echos []bool,
) (answers []string, err error) {
	if len(questions) > 0 {
		c.Env().Require().FailNow("unsupported keyboard-interactive challenge")
	}
	return nil, nil
}
