package reconciler

import (
	"fmt"
	"io"
	"os"

	"github.com/hashicorp/go-multierror"
)

// ReadWriteSeekCloser is a file that can be read, written, seeked, and closed.
type ReadWriteSeekCloser interface {
	io.ReadWriteSeeker
	io.Closer
}

// GetTmpFile returns a temporary file for the reconciler to use.
// TODO: encrypt contents to ensure encryption at rest
func (c *service) GetTmpFile(key string) (ReadWriteSeekCloser, error) {
	fd, err := os.CreateTemp(c.config.tmpDir, fmt.Sprintf("pomerium-bundle-%s", key))
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	return &tmpFile{File: fd}, nil
}

type tmpFile struct {
	*os.File
}

func (f *tmpFile) Close() error {
	var errs *multierror.Error
	if err := f.File.Close(); err != nil {
		errs = multierror.Append(errs, err)
	}
	if err := os.Remove(f.File.Name()); err != nil {
		errs = multierror.Append(errs, err)
	}
	return errs.ErrorOrNil()
}
