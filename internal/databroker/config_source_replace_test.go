package databroker

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// TestConfigSource_SyncerHandlersReplaceRecords covers the handlers behind the
// config source's syncers. On a re-sync they receive the whole record set
// again, and any of them can trigger a rebuild of the config. A handler that
// only clears and then updates lets a rebuild in between publish a config
// without its records, so each one must take the record set in one step.
func TestConfigSource_SyncerHandlersReplaceRecords(t *testing.T) {
	t.Parallel()

	type recordReplacer interface {
		ReplaceRecords(ctx context.Context, serverVersion uint64, records []*databrokerpb.Record)
	}
	for name, handler := range map[string]any{
		"config":           &configSyncerHandler{},
		"versioned config": &versionedConfigSyncerHandler{},
		"key pair":         &entityConfigSyncerHandler[configpb.KeyPair, *configpb.KeyPair]{},
		"policy":           &entityConfigSyncerHandler[configpb.Policy, *configpb.Policy]{},
		"route":            &entityConfigSyncerHandler[configpb.Route, *configpb.Route]{},
		"settings":         &entityConfigSyncerHandler[configpb.Settings, *configpb.Settings]{},
	} {
		_, ok := handler.(recordReplacer)
		assert.Truef(t, ok, "the %s syncer handler cannot replace its records in one step", name)
	}
}
