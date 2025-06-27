package envoyconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
)

func TestBuildSSHListener(t *testing.T) {
	t.Run("no ssh routes or address set", func(t *testing.T) {
		cfg := &config.Config{
			Options: config.NewDefaultOptions(),
		}
		l, err := buildSSHListener(cfg)
		assert.NoError(t, err)
		assert.Nil(t, l)
	})
	t.Run("address set, but no ssh routes", func(t *testing.T) {
		cfg := &config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.Policies = []config.Policy{
			{From: "https://not-ssh", To: mustParseWeightedURLs(t, "https://dest:22")},
		}
		cfg.Options.SSHAddr = "0.0.0.0:22"
		l, err := buildSSHListener(cfg)
		assert.NoError(t, err)
		assert.Nil(t, l)
	})
	t.Run("no address set, but routes present", func(t *testing.T) {
		cfg := &config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.Policies = []config.Policy{
			{From: "ssh://host1", To: mustParseWeightedURLs(t, "ssh://to:22")},
		}
		l, err := buildSSHListener(cfg)
		assert.NoError(t, err)
		assert.Nil(t, l)
	})
	t.Run("address and routes both present", func(t *testing.T) {
		cfg := &config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "0.0.0.0:22"
		cfg.Options.Policies = []config.Policy{
			{From: "ssh://host1", To: mustParseWeightedURLs(t, "ssh://to:22")},
		}
		l, err := buildSSHListener(cfg)
		assert.NoError(t, err)
		assert.NoError(t, l.ValidateAll())
	})
	t.Run("multiple routes", func(t *testing.T) {
		cfg := &config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "0.0.0.0:22"
		cfg.Options.Policies = []config.Policy{
			{From: "ssh://host1", To: mustParseWeightedURLs(t, "ssh://to1:22")},
			{From: "ssh://host2", To: mustParseWeightedURLs(t, "ssh://to2:22")},
			{From: "ssh://host3", To: mustParseWeightedURLs(t, "ssh://to3:22")},
		}
		l, err := buildSSHListener(cfg)
		assert.NoError(t, err)
		assert.NoError(t, l.ValidateAll())
	})
	t.Run("keys configured", func(t *testing.T) {
		cfg := &config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "0.0.0.0:22"
		cfg.Options.SSHHostKeyFiles = &[]string{
			"/path/to/key1",
			"/path/to/key2",
		}
		cfg.Options.SSHHostKeys = &[]string{
			"key3",
			"key4",
		}
		cfg.Options.SSHUserCAKeyFile = "/path/to/user_ca_key"
		cfg.Options.Policies = []config.Policy{
			{From: "ssh://host1", To: mustParseWeightedURLs(t, "ssh://to1:22")},
			{From: "ssh://host2", To: mustParseWeightedURLs(t, "ssh://to2:22")},
			{From: "ssh://host3", To: mustParseWeightedURLs(t, "ssh://to3:22")},
		}
		l, err := buildSSHListener(cfg)
		assert.NoError(t, err)
		assert.NoError(t, l.ValidateAll())
	})
	t.Run("user ca key inline", func(t *testing.T) {
		cfg := &config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "0.0.0.0:22"
		cfg.Options.SSHHostKeyFiles = &[]string{
			"/path/to/key1",
			"/path/to/key2",
		}
		cfg.Options.SSHHostKeys = &[]string{
			"key3",
			"key4",
		}
		cfg.Options.SSHUserCAKey = "key"
		cfg.Options.Policies = []config.Policy{
			{From: "ssh://host1", To: mustParseWeightedURLs(t, "ssh://to1:22")},
			{From: "ssh://host2", To: mustParseWeightedURLs(t, "ssh://to2:22")},
			{From: "ssh://host3", To: mustParseWeightedURLs(t, "ssh://to3:22")},
		}
		l, err := buildSSHListener(cfg)
		assert.NoError(t, err)
		assert.NoError(t, l.ValidateAll())
	})
	t.Run("invalid From url", func(t *testing.T) {
		cfg := &config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "0.0.0.0:22"
		cfg.Options.Policies = []config.Policy{
			{From: "ssh://\x7f", To: mustParseWeightedURLs(t, "ssh://to1:22")},
		}
		_, err := buildSSHListener(cfg)
		assert.Error(t, err)
	})
	t.Run("multiple To urls", func(t *testing.T) {
		cfg := &config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "0.0.0.0:22"
		cfg.Options.Policies = []config.Policy{
			{From: "ssh://host1", To: mustParseWeightedURLs(t, "ssh://to1:22", "ssh://to2:22")},
		}
		_, err := buildSSHListener(cfg)
		assert.Error(t, err)
	})
	t.Run("To url missing scheme", func(t *testing.T) {
		cfg := &config.Config{
			Options: config.NewDefaultOptions(),
		}
		cfg.Options.SSHAddr = "0.0.0.0:22"
		cfg.Options.Policies = []config.Policy{
			{From: "ssh://host1", To: mustParseWeightedURLs(t, "http://to1:22")},
		}
		_, err := buildSSHListener(cfg)
		assert.Error(t, err)
	})
}
