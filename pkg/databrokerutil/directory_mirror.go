package databrokerutil

import (
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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hashicorp/go-set/v3"

	"github.com/pomerium/pomerium/internal/log"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type DirectoryMirror interface {
	Reconcile(ctx context.Context) error
	Watch(ctx context.Context) (stop func())
}

type directoryMirrorFile struct {
	*databrokerpb.File
	Deleted bool
}

type directoryMirror struct {
	client     databrokerpb.DataBrokerServiceClient
	recordType string
	rootDir    string

	mu                           sync.Mutex
	serverVersion, recordVersion uint64
	dataBrokerFiles              map[string]directoryMirrorFile
	fileSystemFiles              map[string]directoryMirrorFile
}

func NewDirectoryMirror(
	client databrokerpb.DataBrokerServiceClient,
	recordType string,
	rootDir string,
) DirectoryMirror {
	return &directoryMirror{
		client:     client,
		recordType: recordType,
		rootDir:    rootDir,

		dataBrokerFiles: make(map[string]directoryMirrorFile),
		fileSystemFiles: make(map[string]directoryMirrorFile),
	}
}

func (d *directoryMirror) Reconcile(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reconcileLocked(ctx)
}

func (d *directoryMirror) Watch(ctx context.Context) (stop func()) {
	return func() {}
}

func (d *directoryMirror) reconcileLocked(ctx context.Context) error {
	err := d.syncDataBrokerLocked(ctx)
	if err != nil {
		return err
	}

	err = d.syncFileSystemLocked(ctx)
	if err != nil {
		return err
	}

	// process databroker deletions
	for p, f := range d.dataBrokerFiles {
		if !f.Deleted {
			continue
		}
		if err := d.deleteLocalFile(ctx, f.File); err != nil {
			return err
		}
		delete(d.dataBrokerFiles, p)
		delete(d.fileSystemFiles, p)
	}

	// process filesystem deletions
	for p, f := range d.fileSystemFiles {
		if !f.Deleted {
			continue
		}
		if err := d.deleteDataBrokerFile(ctx, f.File); err != nil {
			return err
		}
		delete(d.dataBrokerFiles, p)
		delete(d.fileSystemFiles, p)
	}

	paths := set.From(slices.Collect(maps.Keys(d.dataBrokerFiles)))
	paths.InsertSlice(slices.Collect(maps.Keys(d.fileSystemFiles)))
	for p := range paths.Items() {
		f1, ok1 := d.dataBrokerFiles[p]
		f2, ok2 := d.fileSystemFiles[p]

		if ok1 && (!ok2 || f2.ModifiedAt.AsTime().Before(f1.ModifiedAt.AsTime())) {
			if err := d.writeLocalFile(ctx, f1.File); err != nil {
				return err
			}
		} else if ok2 && (!ok1 || f1.ModifiedAt.AsTime().Before(f2.ModifiedAt.AsTime())) {
			if err := d.writeDataBrokerFile(ctx, f2.File); err != nil {
				return err
			}
		}
	}

	return nil
}

func (d *directoryMirror) syncDataBrokerLocked(ctx context.Context) error {
	if d.serverVersion == 0 {
		return d.syncDataBrokerLatestLocked(ctx)
	}

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
			// the server version changed, so use sync latest
			return d.syncDataBrokerLatestLocked(ctx)
		} else if err != nil {
			return fmt.Errorf("directory-mirror: error receving response from sync latest records: %w", err)
		}

		switch res := res.Response.(type) {
		case *databrokerpb.SyncResponse_Record:
			if res.Record.DeletedAt != nil {
				if f, ok := d.dataBrokerFiles[res.Record.Id]; ok {
					f.Deleted = true
					d.dataBrokerFiles[res.Record.Id] = f
				}
			} else {
				var file databrokerpb.File
				if res.Record.Data.UnmarshalTo(&file) == nil {
					d.dataBrokerFiles[res.Record.Id] = directoryMirrorFile{
						File:    &file,
						Deleted: false,
					}
				}
			}
		}
	}

	return nil
}

func (d *directoryMirror) syncDataBrokerLatestLocked(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := d.client.SyncLatest(ctx, &databrokerpb.SyncLatestRequest{
		Type: d.recordType,
	})
	if err != nil {
		return fmt.Errorf("directory-mirror: error syncing latest records: %w", err)
	}

	seen := set.New[string](0)
	for {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("directory-mirror: error receving response from sync latest records: %w", err)
		}

		switch res := res.Response.(type) {
		case *databrokerpb.SyncLatestResponse_Record:
			if res.Record.DeletedAt != nil {
				continue
			}

			var file databrokerpb.File
			if res.Record.Data.UnmarshalTo(&file) == nil {
				seen.Insert(res.Record.Id)
				d.dataBrokerFiles[res.Record.Id] = directoryMirrorFile{
					File:    &file,
					Deleted: false,
				}
			}

		case *databrokerpb.SyncLatestResponse_Versions:
			d.serverVersion = res.Versions.ServerVersion
			d.recordVersion = res.Versions.LatestRecordVersion
		}
	}

	for p, f := range d.dataBrokerFiles {
		if !seen.Contains(p) {
			f.Deleted = true
			d.dataBrokerFiles[p] = f
		}
	}

	return nil
}

func (d *directoryMirror) syncFileSystemLocked(_ context.Context) error {
	seen := set.New[string](0)
	err := filepath.WalkDir(d.rootDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("directory-mirror: error walking file system (filepath=%s): %w", path, err)
		}

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("directory-mirror: error getting file info (filepath=%s): %w", path, err)
		}

		name := d.getFileName(path)
		seen.Insert(name)

		if info.IsDir() {
			d.fileSystemFiles[name] = directoryMirrorFile{
				File: &databrokerpb.File{
					Name:       name,
					Mode:       uint32(info.Mode()),
					ModifiedAt: timestamppb.New(info.ModTime()),
				},
				Deleted: false,
			}
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("directory-mirror: error reading file contents (filepath=%s): %w", path, err)
		}

		d.fileSystemFiles[name] = directoryMirrorFile{
			File: &databrokerpb.File{
				Name:       name,
				Mode:       uint32(info.Mode()),
				ModifiedAt: timestamppb.New(info.ModTime()),
				Data:       data,
			},
			Deleted: false,
		}

		return nil
	})
	if err != nil {
		return err
	}

	// mark deleted files
	for p, f := range d.fileSystemFiles {
		if !seen.Contains(p) {
			f.Deleted = true
			d.fileSystemFiles[p] = f
		}
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
	fullPath := filepath.Join(d.rootDir, file.Name)
	log.Ctx(ctx).Info().Str("filepath", fullPath).Msg("directory-mirror: deleting local file")

	err := os.RemoveAll(fullPath)
	if err != nil {
		return fmt.Errorf("directory-mirror: error deleting local file (filepath=%s): %w", fullPath, err)
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
	fullPath := filepath.Join(d.rootDir, file.Name)
	log.Ctx(ctx).Info().Str("filepath", fullPath).Msg("directory-mirror: writing local file")

	err := os.MkdirAll(filepath.Dir(fullPath), 0o666)
	if err != nil {
		return fmt.Errorf("directory-mirror: error creating parent directories (filepath=%s): %w", fullPath, err)
	}

	if os.FileMode(file.Mode).IsDir() {
		err := os.Mkdir(fullPath, os.FileMode(file.Mode))
		if err != nil && !os.IsExist(err) {
			return fmt.Errorf("directory-mirror: error creating local directory (filepath=%s): %w", fullPath, err)
		}
	} else {
		h, err := os.Create(fullPath)
		if err != nil {
			return fmt.Errorf("directory-mirror: error creating local file (filepath=%s): %w", fullPath, err)
		}

		_, err = h.Write(file.Data)
		if err != nil {
			_ = h.Close()
			return fmt.Errorf("directory-mirror: error writing local file (filepath=%s): %w", fullPath, err)
		}

		err = h.Close()
		if err != nil {
			return fmt.Errorf("directory-mirror: error closing local file (filepath=%s): %w", fullPath, err)
		}
	}

	err = os.Chmod(fullPath, os.FileMode(file.Mode))
	if err != nil {
		return fmt.Errorf("directory-mirror: error changing local file mode (filepath=%s): %w", fullPath, err)
	}

	err = os.Chtimes(fullPath, file.ModifiedAt.AsTime(), file.ModifiedAt.AsTime())
	if err != nil {
		return fmt.Errorf("directory-mirror: error changing local file modification time (filepath=%s): %w", fullPath, err)
	}

	return nil
}

func (d *directoryMirror) getFileName(fullPath string) string {
	p := strings.TrimPrefix(fullPath, d.rootDir)
	p = strings.TrimPrefix(p, "/")
	return p
}
