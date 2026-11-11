package databrokerutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-set/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/fileutil"
	"github.com/pomerium/pomerium/internal/log"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// A DirectoryMirror mirrors a directory to the databroker.
type DirectoryMirror interface {
	// Reconcile reconciles the local directory with the databroker.
	Reconcile(ctx context.Context) error
	// Watch performs a reconciliation and then watches for any changes.
	// Cancel the context to stop watching.
	Watch(ctx context.Context)
}

// DirectoryMirrorMode indicates how the DirectoryMirror should operate.
type DirectoryMirrorMode int

const (
	// DirectoryMirrorModeDataBroker will update the local filesystem to match
	// the databroker as the source of truth.
	DirectoryMirrorModeDataBroker DirectoryMirrorMode = iota
	// DirectoryMirrorModeLocal will update the databroker to match the
	// local filesystem as the source of truth.
	DirectoryMirrorModeLocal
	// DirectoryMirrorModeDataBrokerThenLocal will start by syncing the local
	// filesystem with the databroker, using the databroker as the source of
	// truth, and then subsequent reconcilations will use the local filesystem
	// as the source of truth.
	DirectoryMirrorModeDataBrokerThenLocal
)

type directoryMirrorConfig struct {
	mode        DirectoryMirrorMode
	permissions os.FileMode
}

// DirectoryMirrorOption is an option to customize the directory mirror.
type DirectoryMirrorOption func(cfg *directoryMirrorConfig)

// WithDirectoryMirrorMode sets the mode to use for the directory mirror.
func WithDirectoryMirrorMode(mode DirectoryMirrorMode) DirectoryMirrorOption {
	return func(cfg *directoryMirrorConfig) {
		cfg.mode = mode
	}
}

// WithDirectoryMirrorPermissions sets the permissions to use for files with the directory mirror.
func WithDirectoryMirrorPermissions(permissions os.FileMode) DirectoryMirrorOption {
	return func(cfg *directoryMirrorConfig) {
		cfg.permissions = permissions
	}
}

func getDirectoryMirrorConfig(options ...DirectoryMirrorOption) *directoryMirrorConfig {
	cfg := new(directoryMirrorConfig)
	WithDirectoryMirrorMode(DirectoryMirrorModeDataBrokerThenLocal)(cfg)
	WithDirectoryMirrorPermissions(0o0600)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

type directoryMirror struct {
	client     databrokerpb.DataBrokerServiceClient
	recordType string
	rootDir    string
	cfg        *directoryMirrorConfig

	mu                           sync.Mutex
	serverVersion, recordVersion uint64
	dataBrokerFiles              map[string]*databrokerpb.File
	fileSystemDirectories        *set.Set[string]
	fileSystemFiles              map[string]*databrokerpb.File
	initialized                  bool
}

// NewDirectoryMirror creates a new DirectoryMirror.
func NewDirectoryMirror(
	client databrokerpb.DataBrokerServiceClient,
	recordType string,
	rootDir string,
	options ...DirectoryMirrorOption,
) DirectoryMirror {
	return &directoryMirror{
		client:     client,
		recordType: recordType,
		rootDir:    rootDir,
		cfg:        getDirectoryMirrorConfig(options...),

		dataBrokerFiles:       make(map[string]*databrokerpb.File),
		fileSystemDirectories: set.New[string](0),
		fileSystemFiles:       make(map[string]*databrokerpb.File),
	}
}

// Reconcile reconciles the local directory with the databroker one time.
func (d *directoryMirror) Reconcile(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reconcileLocked(ctx)
}

// Watch watches the local directory and the databroker continuously for changes.
// It blocks until context is Done.
func (d *directoryMirror) Watch(ctx context.Context) {
	err := d.retry(ctx, func() error { return d.Reconcile(ctx) })
	if err != nil {
		return
	}

	switch d.cfg.mode {
	case DirectoryMirrorModeDataBroker:
		d.watchDataBrokerToLocal(ctx)
	case DirectoryMirrorModeDataBrokerThenLocal, DirectoryMirrorModeLocal:
		d.watchLocalToDataBroker(ctx)
	default:
		panic(fmt.Errorf("unknown directory mirror mode: %d", d.cfg.mode))
	}
}

func (d *directoryMirror) watchDataBrokerToLocal(ctx context.Context) {
	b := backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(0))
	update := func() error {
		d.mu.Lock()
		defer d.mu.Unlock()
		if err := d.loadFileSystemRecordsLocked(ctx); err != nil {
			return err
		}
		return d.syncDataBrokerToLocalLocked(ctx)
	}
	syncLatest := func() error {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		var serverVersion, recordVersion uint64
		dataBrokerFiles := map[string]*databrokerpb.File{}

		stream, err := d.client.SyncLatest(ctx, &databrokerpb.SyncLatestRequest{
			Type: d.recordType,
		})
		if err != nil {
			return fmt.Errorf("directory-mirror: error syncing latest records: %w", err)
		}

		b.Reset()

		for {
			res, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return fmt.Errorf("directory-mirror: error receiving sync latest records response: %w", err)
			}

			switch res := res.Response.(type) {
			case *databrokerpb.SyncLatestResponse_Versions:
				serverVersion, recordVersion = res.Versions.ServerVersion, res.Versions.LatestRecordVersion
			case *databrokerpb.SyncLatestResponse_Record:
				if res.Record.DeletedAt == nil {
					var file databrokerpb.File
					if res.Record.Data.UnmarshalTo(&file) == nil {
						dataBrokerFiles[res.Record.Id] = &file
					}
				}
			}
		}

		d.mu.Lock()
		d.dataBrokerFiles = dataBrokerFiles
		d.serverVersion = serverVersion
		d.recordVersion = recordVersion
		d.mu.Unlock()

		return update()
	}
	syncChanges := func() error {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		d.mu.Lock()
		serverVersion, recordVersion := d.serverVersion, d.recordVersion
		d.mu.Unlock()

		stream, err := d.client.Sync(ctx, &databrokerpb.SyncRequest{
			Type:          d.recordType,
			ServerVersion: serverVersion,
			RecordVersion: recordVersion,
			Wait:          new(true),
		})
		if err != nil {
			return fmt.Errorf("directory-mirror: error syncing records: %w", err)
		}

		for {
			res, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			} else if status.Code(err) == codes.Aborted {
				cancel()
				return syncLatest()
			} else if err != nil {
				return fmt.Errorf("directory-mirror: error receiving sync records response: %w", err)
			}

			b.Reset()

			switch res := res.Response.(type) {
			case *databrokerpb.SyncResponse_Record:
				d.mu.Lock()
				if res.Record.DeletedAt == nil {
					var file databrokerpb.File
					if res.Record.Data.UnmarshalTo(&file) == nil {
						d.dataBrokerFiles[res.Record.Id] = &file
					} else {
						delete(d.dataBrokerFiles, res.Record.Id)
					}
				} else {
					delete(d.dataBrokerFiles, res.Record.Id)
				}
				d.recordVersion = max(d.recordVersion, res.Record.Version)
				d.mu.Unlock()
				if err := update(); err != nil {
					return err
				}
			}
		}

		return nil
	}

	for {
		err := syncChanges()
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("directory-mirror: error watching databroker for changes")
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(b.NextBackOff()):
		}
	}
}

func (d *directoryMirror) watchLocalToDataBroker(ctx context.Context) {
	w := fileutil.NewWatcher()
	defer w.Close()
	ch := w.Bind()
	defer w.Unbind(ch)

	for {
		err := d.retry(ctx, func() error {
			d.mu.Lock()
			defer d.mu.Unlock()

			err := d.loadFileSystemRecordsLocked(ctx)
			if err != nil {
				return err
			}
			w.Watch(d.getWatchPathsLocked())

			err = d.loadDataBrokerRecordsLocked(ctx)
			if err != nil {
				return err
			}

			return d.syncLocalToDataBrokerLocked(ctx)
		})
		if err != nil {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ch:
		}
	}
}

func (d *directoryMirror) reconcileLocked(ctx context.Context) error {
	err := d.loadDataBrokerRecordsLocked(ctx)
	if err != nil {
		return err
	}

	err = d.loadFileSystemRecordsLocked(ctx)
	if err != nil {
		return err
	}

	switch d.cfg.mode {
	case DirectoryMirrorModeDataBroker:
		return d.syncDataBrokerToLocalLocked(ctx)
	case DirectoryMirrorModeDataBrokerThenLocal:
		if d.initialized {
			return d.syncLocalToDataBrokerLocked(ctx)
		}
		err := d.syncDataBrokerToLocalLocked(ctx)
		if err != nil {
			return err
		}
		d.initialized = true
		return nil
	case DirectoryMirrorModeLocal:
		return d.syncLocalToDataBrokerLocked(ctx)
	default:
		panic(fmt.Errorf("unknown directory mirror mode: %d", d.cfg.mode))
	}
}

func (d *directoryMirror) syncLocalToDataBrokerLocked(ctx context.Context) error {
	paths := set.TreeSetFrom(slices.Collect(maps.Keys(d.dataBrokerFiles)), strings.Compare)
	paths.InsertSlice(slices.Collect(maps.Keys(d.fileSystemFiles)))
	for p := range paths.Items() {
		f1, ok1 := d.dataBrokerFiles[p]
		f2, ok2 := d.fileSystemFiles[p]
		if ok1 && !ok2 {
			// a file in the databroker does not exist locally, so delete it
			if err := d.deleteDataBrokerFile(ctx, f1); err != nil {
				return err
			}
		} else if ok2 && (!ok1 || !bytes.Equal(f1.Data, f2.Data)) {
			// a file in the databroker is different from a local file
			if err := d.writeDataBrokerFile(ctx, f2); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *directoryMirror) syncDataBrokerToLocalLocked(ctx context.Context) error {
	paths := set.TreeSetFrom(slices.Collect(maps.Keys(d.dataBrokerFiles)), strings.Compare)
	paths.InsertSlice(slices.Collect(maps.Keys(d.fileSystemFiles)))
	for p := range paths.Items() {
		f1, ok1 := d.dataBrokerFiles[p]
		f2, ok2 := d.fileSystemFiles[p]
		if ok2 && !ok1 {
			// a local file does not exist in the databroker, so delete it
			if err := d.deleteLocalFile(ctx, f2); err != nil {
				return err
			}
		} else if ok1 && (!ok2 || !bytes.Equal(f1.Data, f2.Data)) {
			// a local file does not match the databroker, so update it
			if err := d.writeLocalFile(ctx, f1); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *directoryMirror) loadDataBrokerRecordsLocked(ctx context.Context) error {
	syncLatest := func() error {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		var serverVersion, recordVersion uint64
		dataBrokerFiles := map[string]*databrokerpb.File{}

		stream, err := d.client.SyncLatest(ctx, &databrokerpb.SyncLatestRequest{
			Type: d.recordType,
		})
		if err != nil {
			return fmt.Errorf("directory-mirror: error syncing latest records: %w", err)
		}

		for {
			res, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return fmt.Errorf("directory-mirror: error receiving sync latest records response: %w", err)
			}

			switch res := res.Response.(type) {
			case *databrokerpb.SyncLatestResponse_Versions:
				serverVersion, recordVersion = res.Versions.ServerVersion, res.Versions.LatestRecordVersion
			case *databrokerpb.SyncLatestResponse_Record:
				var file databrokerpb.File
				if res.Record.Data.UnmarshalTo(&file) == nil {
					dataBrokerFiles[res.Record.Id] = &file
				}
			}
		}

		d.serverVersion = serverVersion
		d.recordVersion = recordVersion
		d.dataBrokerFiles = dataBrokerFiles

		return nil
	}
	syncChanges := func() error {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		stream, err := d.client.Sync(ctx, &databrokerpb.SyncRequest{
			Type:          d.recordType,
			ServerVersion: d.serverVersion,
			RecordVersion: d.recordVersion,
			Wait:          new(false),
		})
		if err != nil {
			return fmt.Errorf("directory-mirror: error syncing records: %w", err)
		}

		for {
			res, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			} else if status.Code(err) == codes.Aborted {
				cancel()
				return syncLatest()
			} else if err != nil {
				return fmt.Errorf("directory-mirror: error receiving sync records response: %w", err)
			}

			switch res := res.Response.(type) {
			case *databrokerpb.SyncResponse_Record:
				if res.Record.DeletedAt == nil {
					var file databrokerpb.File
					if res.Record.Data.UnmarshalTo(&file) == nil {
						d.dataBrokerFiles[res.Record.Id] = &file
					} else {
						delete(d.dataBrokerFiles, res.Record.Id)
					}
				} else {
					delete(d.dataBrokerFiles, res.Record.Id)
				}
				d.recordVersion = max(d.recordVersion, res.Record.Version)
			}
		}

		return nil
	}
	if d.serverVersion == 0 {
		return syncLatest()
	}
	return syncChanges()
}

// getWatchPathsLocked returns the absolute paths of all the local files and
// directories
func (d *directoryMirror) getWatchPathsLocked() []string {
	paths := set.NewTreeSet(strings.Compare)
	paths.Insert(d.rootDir)
	for p := range d.fileSystemDirectories.Items() {
		paths.Insert(filepath.Join(d.rootDir, p))
	}
	for p := range d.fileSystemFiles {
		paths.Insert(filepath.Join(d.rootDir, p))
	}
	return paths.Slice()
}

func (d *directoryMirror) loadFileSystemRecordsLocked(_ context.Context) error {
	d.fileSystemDirectories = set.New[string](0)
	clear(d.fileSystemFiles)

	root, err := d.getRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("directory-mirror: error walking file system (filename=%s): %w", name, err)
		}

		if entry.IsDir() {
			d.fileSystemDirectories.Insert(name)
			return nil
		}

		// WalkDir does not follow symlinks, so a symlink to a directory shows up
		// as a non-directory entry. Skip it rather than failing to read it.
		if entry.Type()&fs.ModeSymlink != 0 {
			if info, err := root.Stat(name); err == nil && info.IsDir() {
				return nil
			}
		}

		data, err := root.ReadFile(name)
		if err != nil {
			return fmt.Errorf("directory-mirror: error reading file contents (filename=%s): %w", name, err)
		}

		d.fileSystemFiles[name] = &databrokerpb.File{
			Name: name,
			Data: data,
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (d *directoryMirror) deleteDataBrokerFile(ctx context.Context, file *databrokerpb.File) error {
	log.Ctx(ctx).Info().Str("filename", file.Name).Msg("directory-mirror: deleting databroker file")
	_, err := d.client.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{
			Type:      d.recordType,
			Id:        file.Name,
			Data:      protoutil.NewAny(file),
			DeletedAt: timestamppb.Now(),
		}},
	})
	if err != nil {
		return fmt.Errorf("directory-mirror: error deleting databroker file (filename=%s): %w", file.Name, err)
	}
	return nil
}

func (d *directoryMirror) deleteLocalFile(ctx context.Context, file *databrokerpb.File) error {
	log.Ctx(ctx).Info().Str("filename", file.Name).Msg("directory-mirror: deleting local file")

	root, err := d.getRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	err = root.RemoveAll(file.Name)
	if err != nil {
		return fmt.Errorf("directory-mirror: error deleting local file (filename=%s): %w", file.Name, err)
	}

	return nil
}

func (d *directoryMirror) writeDataBrokerFile(ctx context.Context, file *databrokerpb.File) error {
	log.Ctx(ctx).Info().Str("filename", file.Name).Msg("directory-mirror: writing databroker file")
	_, err := d.client.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{
			Type: d.recordType,
			Id:   file.Name,
			Data: protoutil.NewAny(file),
		}},
	})
	if err != nil {
		return fmt.Errorf("directory-mirror: error writing databroker file (filename=%s): %w", file.Name, err)
	}
	return nil
}

func (d *directoryMirror) writeLocalFile(ctx context.Context, file *databrokerpb.File) error {
	log.Ctx(ctx).Info().Str("filename", file.Name).Msg("directory-mirror: writing local file")

	root, err := d.getRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	err = root.MkdirAll(filepath.Dir(file.Name), d.getDirectoryPermissions())
	if err != nil {
		return fmt.Errorf("directory-mirror: error creating parent directories (filename=%s): %w", file.Name, err)
	}

	err = root.WriteFile(file.Name, file.Data, d.cfg.permissions)
	if err != nil {
		return fmt.Errorf("directory-mirror: error writing local file (filename=%s): %w", file.Name, err)
	}

	return nil
}

func (d *directoryMirror) getRoot() (*os.Root, error) {
	err := os.MkdirAll(d.rootDir, d.getDirectoryPermissions())
	if err != nil {
		return nil, fmt.Errorf("directory-mirror: error creating root directory (filepath=%s): %w", d.rootDir, err)
	}
	root, err := os.OpenRoot(d.rootDir)
	if err != nil {
		return nil, fmt.Errorf("directory-mirror: error opening root directory (filepath=%s): %w", d.rootDir, err)
	}
	return root, nil
}

func (d *directoryMirror) getDirectoryPermissions() os.FileMode {
	return d.cfg.permissions | (d.cfg.permissions&0o444)>>2
}

func (d *directoryMirror) retry(ctx context.Context, fn func() error) error {
	return backoff.RetryNotify(
		fn,
		backoff.WithContext(backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(0)), ctx),
		func(err error, d time.Duration) {
			log.Error().
				Err(err).
				Dur("delay", d).
				Msg("directory-mirror: error performing operation")
		},
	)
}
