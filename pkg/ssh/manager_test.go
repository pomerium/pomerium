package ssh_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/ssh"
	mock_ssh "github.com/pomerium/pomerium/pkg/ssh/mock"
)

func mustParseWeightedURLs(t *testing.T, urls ...string) []config.WeightedURL {
	wu, err := config.ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}

func TestStreamManager(t *testing.T) {
	ctrl := gomock.NewController(t)
	auth := mock_ssh.NewMockAuthInterface(ctrl)

	cfg := &config.Config{Options: config.NewDefaultOptions()}
	cfg.Options.Policies = []config.Policy{
		{From: "ssh://host1", To: mustParseWeightedURLs(t, "ssh://dest1:22")},
		{From: "ssh://host2", To: mustParseWeightedURLs(t, "ssh://dest2:22")},
	}
	m := ssh.NewStreamManager(t.Context(), auth, cfg)

	t.Run("LookupStream", func(t *testing.T) {
		assert.Nil(t, m.LookupStream(1234))
		sh := m.NewStreamHandler(&extensions_ssh.DownstreamConnectEvent{StreamId: 1234})
		assert.Equal(t, sh, m.LookupStream(1234))
		sh.Close()
		assert.Nil(t, m.LookupStream(1234))
	})
}
