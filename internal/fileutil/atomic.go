package fileutil

import (
	"os"
	"path/filepath"
)

// WriteFileAtomically writes to a file path atomically. It does this by creating a temporary
// file in the same directory and then renaming it. If anything goes wrong the temporary
// file is deleted.
func WriteFileAtomically(filePath string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(filePath), filepath.Base(filePath)+".tmp")
	if err != nil {
		return err
	}
	tmpPath := f.Name()

	err = writeFileAndClose(f, data, mode)
	if err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	err = os.Rename(tmpPath, filePath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	return nil
}

func writeFileAndClose(f *os.File, data []byte, mode os.FileMode) error {
	_, err := f.Write(data)
	if err != nil {
		_ = f.Close()
		return err
	}

	err = f.Sync()
	if err != nil {
		_ = f.Close()
		return err
	}

	err = f.Chmod(mode)
	if err != nil {
		_ = f.Close()
		return err
	}

	err = f.Close()
	if err != nil {
		return err
	}

	return nil
}
