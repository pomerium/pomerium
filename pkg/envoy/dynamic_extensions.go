package envoy

import (
	"context"
	"errors"
	"fmt"
	"slices"

	xds_type_v3 "github.com/cncf/xds/go/xds/type/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	dynamic_extension_loader "github.com/pomerium/envoy-custom/api/extensions/bootstrap/dynamic_extension_loader"
	xssh "github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/recording"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type DynamicExtensionsConfig struct {
	RecordingPipes    []*recording.Pipes
	DynamicExtensions *envoy_config_core_v3.TypedExtensionConfig
	extensionIDs      []string
}

func (d *DynamicExtensionsConfig) isSessionRecordingEnabled() bool {
	return slices.Contains(d.extensionIDs, envoyconfig.ExtensionSSHSessionRecording)
}

func (srv *Server) configureDynamicExtensions(ctx context.Context, cfg *config.Config, paths []string) (*DynamicExtensionsConfig, error) {
	out := &DynamicExtensionsConfig{}
	extensionLoaderCfg := &dynamic_extension_loader.Config{
		Paths:            paths,
		ExtensionConfigs: map[string]*anypb.Any{},
	}
	for _, filepath := range paths {
		extID, err := envoyconfig.ReadDynamicExtensionID(ctx, filepath)
		if err != nil {
			return nil, err
		}
		switch extID {
		case envoyconfig.ExtensionSSHSessionRecording:
			pipes, err := srv.configureSessionRecordingExtension(ctx, cfg, extensionLoaderCfg, extID)
			if err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to configure ssh dynamic extension")
				if pipes != nil {
					log.Ctx(ctx).Debug().Msg("cleaning up constructed pipes for session recording due to config failure")
					errs := []error{}
					for _, pipe := range pipes {
						errs = append(errs, pipe.Close())
					}
					if closeErr := errors.Join(errs...); closeErr != nil {
						log.Ctx(ctx).Err(closeErr).Msg("failed to cleanup pipes")
					}
				}
			}
			out.RecordingPipes = pipes
		}
		out.extensionIDs = append(out.extensionIDs, extID)
	}
	out.DynamicExtensions = &envoy_config_core_v3.TypedExtensionConfig{
		Name:        "envoy.bootstrap.dynamic_extension_loader",
		TypedConfig: marshalAny(extensionLoaderCfg),
	}
	return out, nil
}

// mutates the extension loader in place
func (srv *Server) configureSessionRecordingExtension(
	_ context.Context,
	cfg *config.Config,
	dynCfg *dynamic_extension_loader.Config,
	extID string,
) ([]*recording.Pipes, error) {
	sshCfg := &xssh.Config{
		UploadConfig: &xssh.UploadConfig{
			DefaultBufferSize: 1024 * 1024 * 32,
			Concurrency: &wrapperspb.UInt32Value{
				Value: cfg.Options.SessionRecordingConcurrency.GetValueOr(8),
			},
			IpcMode: &xssh.UploadConfig_PipeIpc_{
				PipeIpc: &xssh.UploadConfig_PipeIpc{},
			},
		},
	}
	pipes, err := recording.SetupRecordingPipes(sshCfg)
	if err != nil {
		return nil, fmt.Errorf("configuring %s extension: %w", extID, err)
	}
	ext := protoutil.NewAny(sshCfg)
	ts := &xds_type_v3.TypedStruct{
		TypeUrl: ext.TypeUrl,
		Value:   &structpb.Struct{},
	}
	msg, err := ext.UnmarshalNew()
	if err != nil {
		return pipes, fmt.Errorf("unmarshalling %s extension config: %w", extID, err)
	}
	data, err := protojson.Marshal(msg)
	if err != nil {
		return pipes, fmt.Errorf("marshalling %s extension config: %w", extID, err)
	}
	if err := protojson.Unmarshal(data, ts.Value); err != nil {
		return pipes, err
	}
	dynCfg.ExtensionConfigs[extID] = marshalAny(ts)
	return pipes, nil
}
