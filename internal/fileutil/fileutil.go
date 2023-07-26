// Package fileutil provides file utility functions, complementing the
// lower level abstractions found in the standard library.
package fileutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

// ReadFileUpTo reads file up to given size
// it returns an error if file is larger than allowed maximum
func ReadFileUpTo(fname string, maxSize int64) ([]byte, error) {
	var buf bytes.Buffer
	if err := CopyFileUpTo(&buf, fname, maxSize); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CopyFileUpTo copies content of the file up to maxBytes
// it returns an error if file is larger than allowed maximum
func CopyFileUpTo(dst io.Writer, fname string, maxBytes int64) error {
	fd, err := os.Open(fname)
	if err != nil {
		return fmt.Errorf("open %s: %w", fname, err)
	}
	defer func() { _ = fd.Close() }()

	fi, err := fd.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", fname, err)
	}
	if fi.Size() > maxBytes {
		return fmt.Errorf("file %s size %d > max %d", fname, fi.Size(), maxBytes)
	}

	if _, err := io.Copy(dst, fd); err != nil {
		return fmt.Errorf("read %s: %w", fname, err)
	}

	return nil
}
