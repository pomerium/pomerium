package bootstrap

import (
	"context"
	"encoding/base64"
	"net/netip"
	"strings"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/log"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
)

var _ = config.Source(new(source))

var cmpOpts = []cmp.Option{
	cmpopts.IgnoreUnexported(config.Options{}),
	cmpopts.EquateEmpty(),
	cmpopts.EquateComparable(netip.AddrPort{}, netip.Addr{}),
}

type source struct {
	cfg atomicutil.Value[*config.Config]

	listenerLock sync.RWMutex
	listeners    []config.ChangeListener

	ready     chan struct{}
	markReady sync.Once
}

func (src *source) WaitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-src.ready:
		return nil
	}
}

// GetConfig implements config.Source
func (src *source) GetConfig() *config.Config {
	return src.cfg.Load()
}

// OnConfigChange implements config.Source
func (src *source) OnConfigChange(_ context.Context, l config.ChangeListener) {
	src.listenerLock.Lock()
	src.listeners = append(src.listeners, l)
	src.listenerLock.Unlock()
}

// UpdateBootstrap updates the underlying configuration options
func (src *source) UpdateBootstrap(ctx context.Context, cfg cluster_api.BootstrapConfig) bool {
	current := src.cfg.Load()
	incoming := current.Clone()
	applyBootstrapConfig(incoming, &cfg)

	if cmp.Equal(incoming, current, cmpOpts...) {
		return false
	}

	src.cfg.Store(incoming)
	src.markReady.Do(func() {
		log.Ctx(ctx).Info().
			Str("organization-id", cfg.OrganizationId).
			Str("cluster-id", cfg.ClusterId).
			Msg("loaded Pomerium Zero bootstrap config")
		close(src.ready)
	})

	src.notifyListeners(ctx, incoming)

	return true
}

// notifyListeners notifies all listeners of a configuration change
func (src *source) notifyListeners(ctx context.Context, cfg *config.Config) {
	src.listenerLock.RLock()
	listeners := make([]config.ChangeListener, len(src.listeners))
	copy(listeners, src.listeners)
	src.listenerLock.RUnlock()

	for _, l := range listeners {
		l(ctx, cfg)
	}
}

func applyBootstrapConfig(dst *config.Config, src *cluster_api.BootstrapConfig) {
	dst.Options.SharedKey = base64.StdEncoding.EncodeToString(src.SharedSecret)
	if src.DatabrokerStorageConnection != nil {
		if strings.HasPrefix(*src.DatabrokerStorageConnection, "file://") {
			dst.Options.DataBroker.StorageType = config.StorageFileName
			dst.Options.DataBroker.StorageConnectionString = *src.DatabrokerStorageConnection
		} else {
			dst.Options.DataBroker.StorageType = config.StoragePostgresName
			dst.Options.DataBroker.StorageConnectionString = *src.DatabrokerStorageConnection
		}
	} else {
		dst.Options.DataBroker.StorageType = config.StorageInMemoryName
		dst.Options.DataBroker.StorageConnectionString = ""
	}
	dst.ZeroClusterID = src.ClusterId
	dst.ZeroOrganizationID = src.OrganizationId
	dst.ZeroPseudonymizationKey = src.PseudonymizationKey
}
