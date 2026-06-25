package envoy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	xds_type_v3 "github.com/cncf/xds/go/xds/type/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/hashicorp/go-set/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	dynamic_extension_loader "github.com/pomerium/envoy-custom/api/extensions/bootstrap/dynamic_extension_loader"
	xrecording "github.com/pomerium/envoy-custom/api/x/recording"
	xssh "github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/ipc"
	"github.com/pomerium/pomerium/pkg/protoutil"
	slicesutil "github.com/pomerium/pomerium/pkg/slices"
)

type dynamicExtension struct {
	id   string
	path string
}

type extensionStatusInfo struct {
	Loaded []extensionLoadedInfo `json:"loaded,omitempty"`
	Failed []extensionFailedInfo `json:"failed,omitempty"`
}

type extensionLoadedInfo struct {
	ID string `json:"id"`
}

type extensionFailedInfo struct {
	Info extensionInfo `json:"info"`
	Err  string        `json:"err"`
}

type extensionInfo struct {
	Path string `json:"path"`
}

type DynamicExtensionsConfig struct {
	RecordingPipes    []*ipc.ProtoPipeWorker[*xrecording.RecordingData, *xrecording.RecordingCheckpoint]
	DynamicExtensions *envoy_config_core_v3.TypedExtensionConfig
	extensions        []dynamicExtension
}

func (d *DynamicExtensionsConfig) extensionIDs() []string {
	return slicesutil.Map(d.extensions, func(d dynamicExtension) string {
		return d.id
	})
}

func (d *DynamicExtensionsConfig) isSessionRecordingEnabled() bool {
	return slices.Contains(d.extensionIDs(), envoyconfig.ExtensionSSHSessionRecording)
}

func (srv *Server) configureDynamicExtensions(ctx context.Context, cfg *config.Config, paths []string) (*DynamicExtensionsConfig, error) {
	out := &DynamicExtensionsConfig{}
	extensionLoaderCfg := &dynamic_extension_loader.Config{
		Paths:            paths,
		ExtensionConfigs: map[string]*anypb.Any{},
	}
	for _, extPath := range paths {
		extID, err := envoyconfig.ReadDynamicExtensionID(ctx, extPath)
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
		out.extensions = append(out.extensions, dynamicExtension{
			id:   extID,
			path: extPath,
		})
	}
	out.DynamicExtensions = &envoy_config_core_v3.TypedExtensionConfig{
		Name:        "envoy.bootstrap.dynamic_extension_loader",
		TypedConfig: marshalAny(extensionLoaderCfg),
	}
	return out, nil
}

func (srv *Server) startDynExtHealthProbeLocked(ctx context.Context, dynCfg *DynamicExtensionsConfig) {
	if srv.dynamicExtensionHealthProbeCancel != nil {
		srv.dynamicExtensionHealthProbeCancel()
	}
	ctxca, ca := context.WithCancel(ctx)
	srv.dynamicExtensionHealthProbeCancel = ca
	go srv.probeExtensionHealth(ctxca, dynCfg.extensions)
}

// mutates the extension loader in place
func (srv *Server) configureSessionRecordingExtension(
	_ context.Context,
	cfg *config.Config,
	dynCfg *dynamic_extension_loader.Config,
	extID string,
) ([]*ipc.ProtoPipeWorker[*xrecording.RecordingData, *xrecording.RecordingCheckpoint], error) {
	conc := cfg.Options.SessionRecordingConcurrency.Or(8)
	workers, err := ipc.NewPipeWorkers[*xrecording.RecordingData, *xrecording.RecordingCheckpoint](int(conc))
	if err != nil {
		return nil, fmt.Errorf("configuring %s extension: %w", extID, err)
	}

	sshCfg := &xssh.Config{
		UploadConfig: &xssh.UploadConfig{
			DefaultBufferSize: 1024 * 1024 * 32,
			Concurrency: &wrapperspb.UInt32Value{
				Value: conc,
			},
			IpcMode: &xssh.UploadConfig_PipeIpc_{
				PipeIpc: &xssh.UploadConfig_PipeIpc{},
			},
		},
	}
	ext := protoutil.NewAny(sshCfg)
	ts := &xds_type_v3.TypedStruct{
		TypeUrl: ext.TypeUrl,
		Value:   &structpb.Struct{},
	}
	msg, err := ext.UnmarshalNew()
	if err != nil {
		return workers, fmt.Errorf("unmarshalling %s extension config: %w", extID, err)
	}
	data, err := protojson.Marshal(msg)
	if err != nil {
		return workers, fmt.Errorf("marshalling %s extension config: %w", extID, err)
	}
	if err := protojson.Unmarshal(data, ts.Value); err != nil {
		return workers, err
	}
	dynCfg.ExtensionConfigs[extID] = marshalAny(ts)
	return workers, nil
}

func (srv *Server) probeExtensionHealth(ctx context.Context, configuredExtensions []dynamicExtension) {
	log.Ctx(ctx).Debug().Msg("starting envoy dynamic extension health probe")
	defer func() {
		log.Ctx(ctx).Debug().Msg("envoy dynamic extension health probe done")
	}()
	if len(configuredExtensions) == 0 {
		health.ReportRunning(health.EnvoyDynamicExtensions)
		return
	}
	health.ReportError(health.EnvoyDynamicExtensions, fmt.Errorf("waiting for status to be reported"))
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			info, err := srv.envoyDynamicExtStatus(ctx)
			if err != nil {
				health.ReportError(health.EnvoyDynamicExtensions, fmt.Errorf("failed to check extension status : %w", err))
			} else {
				remaining, md, err := srv.compareExtensions(configuredExtensions, info)
				if err != nil {
					health.ReportError(health.EnvoyDynamicExtensions, err, md...)
				} else {
					health.ReportRunning(health.EnvoyDynamicExtensions, md...)
				}
				if len(remaining) == 0 {
					return
				}
			}
		}
	}
}

func (srv *Server) envoyDynamicExtStatus(ctx context.Context) (*extensionStatusInfo, error) {
	srv.mu.Lock()
	adminAddress := srv.adminAddress
	srv.mu.Unlock()

	u := &url.URL{
		Scheme: "http",
		Host:   "unix",
		Path:   "/dynamic_extensions/status",
	}
	client := envoyAdminClient(adminAddress)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected http status code from dynamic extensions status : %d", resp.StatusCode)
	}

	dec := json.NewDecoder(resp.Body)
	info := &extensionStatusInfo{}
	if err := dec.Decode(info); err != nil {
		return nil, err
	}
	return info, nil
}

func (srv *Server) compareExtensions(configuredExtensions []dynamicExtension, info *extensionStatusInfo) (notReported []string, metadata []health.Attr, err error) {
	if len(configuredExtensions) == 0 {
		return []string{}, []health.Attr{}, nil
	}

	extIDsToCheck := set.New[string](len(configuredExtensions))
	filePathsToID := map[string]string{}
	for _, ext := range configuredExtensions {
		extIDsToCheck.Insert(ext.id)
		filePathsToID[ext.path] = ext.id
	}

	for _, loadedExt := range info.Loaded {
		_ = extIDsToCheck.Remove(loadedExt.ID)
	}

	if extIDsToCheck.Size() == 0 {
		return []string{}, slicesutil.Map(configuredExtensions, func(ext dynamicExtension) health.Attr {
			return health.StrAttr(ext.id, "loaded")
		}), nil
	}
	retAttrs := []health.Attr{}
	for _, failedExt := range info.Failed {
		id, ok := filePathsToID[failedExt.Info.Path]
		if !ok {
			continue
		}
		_ = extIDsToCheck.Remove(id)
		if failedExt.Err != "" {
			retAttrs = append(retAttrs, health.StrAttr(id, fmt.Sprintf("extension failed to load : %s", failedExt.Err)))
		} else {
			retAttrs = append(retAttrs, health.StrAttr(id, "extension failed to load"))
		}
	}
	for _, remainingID := range extIDsToCheck.Slice() {
		retAttrs = append(retAttrs, health.StrAttr(remainingID, "health not reported"))
	}
	return extIDsToCheck.Slice(), retAttrs, fmt.Errorf("not all configured extensions loaded")
}
