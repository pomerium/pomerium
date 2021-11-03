package cli

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

const maxConfigFileBytes = 4 << 20

// FileConfigProvider implements file based configuration storage
type FileConfigProvider string

// Load loads file data or returns empty data if it does not exist
func (f FileConfigProvider) Load() ([]byte, error) {
	fd, err := os.Open(string(f))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	defer func() { _ = fd.Close() }()
	return io.ReadAll(io.LimitReader(fd, maxConfigFileBytes))
}

// Save stores data to the file
func (f FileConfigProvider) Save(data []byte) error {
	return os.WriteFile(string(f), data, 0600)
}
