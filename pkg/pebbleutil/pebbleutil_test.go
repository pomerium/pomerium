package pebbleutil

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/pebble/v2"
)

func TestSecureFSFileAndDirPerms(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbDir := filepath.Join(dir, "db")
	db, err := Open(dbDir, nil)
	if err != nil {
		t.Fatalf("open pebble: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	wo := &pebble.WriteOptions{Sync: true}
	val := bytes.Repeat([]byte{'v'}, 4096)
	for i := 0; i < 200; i++ {
		k := []byte(fmt.Sprintf("k%06d", i))
		if err := db.Set(k, val, wo); err != nil {
			t.Fatalf("set: %v", err)
		}
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	var foundFile bool
	err = filepath.Walk(dbDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		mode := info.Mode().Perm()
		if info.IsDir() {
			if mode != 0o700 {
				t.Errorf("dir %s mode = %o, want 0700", path, mode)
			}
			return nil
		}
		base := filepath.Base(path)
		if base == "LOCK" {
			// Pebble seems to manage LOCK file separately
			return nil
		}
		foundFile = true
		if mode != 0o600 {
			t.Errorf("file %s mode = %o, want 0600", path, mode)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if !foundFile {
		t.Fatalf("no files found in pebble dir; test invalid")
	}
}

func TestMustOpenMemoryUnchanged(t *testing.T) {
	t.Parallel()
	db := MustOpenMemory(nil)
	t.Cleanup(func() { _ = db.Close() })
	wo := &pebble.WriteOptions{Sync: true}
	if err := db.Set([]byte("k"), []byte("v"), wo); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}
