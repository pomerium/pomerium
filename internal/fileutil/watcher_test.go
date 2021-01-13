package fileutil

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestWatcher(t *testing.T) {
	tmpdir := filepath.Join(os.TempDir(), uuid.New().String())
	err := os.MkdirAll(tmpdir, 0o755)
	if !assert.NoError(t, err) {
		return
	}

	err = ioutil.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{1, 2, 3, 4}, 0o666)
	if !assert.NoError(t, err) {
		return
	}

	w := NewWatcher()
	w.Add(filepath.Join(tmpdir, "test1.txt"))

	ch := w.Bind()
	defer w.Unbind(ch)

	err = ioutil.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{5, 6, 7, 8}, 0o666)
	if !assert.NoError(t, err) {
		return
	}

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Error("expected change signal when file is modified")
	}
}
