package fileutil // import "github.com/pomerium/pomerium/internal/fileutil"

import (
	"errors"
	"os"
)

// IsReadableFile reports whether the file exists and is readable.
// If the error is non-nil, it means there might be a file or directory
// with that name but we cannot read it.
//
// Adapted from the upspin.io source code.
func IsReadableFile(path string) (bool, error) {
	// Is it stattable and is it a plain file?
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // Item does not exist.
		}
		return false, err // Item is problematic.
	}
	if info.IsDir() {
		return false, errors.New("is directory")
	}
	// Is it readable?
	fd, err := os.Open(path)
	if err != nil {
		return false, errors.New("permission denied")
	}
	fd.Close()
	return true, nil // Item exists and is readable.
}

// Getwd returns a rooted path name corresponding to the
// current directory. If the current directory can be
// reached via multiple paths (due to symbolic links),
// Getwd may return any one of them.
//
// On failure, will return "."
func Getwd() string {
	p, err := os.Getwd()
	if err != nil {
		return "."
	}
	return p
}
