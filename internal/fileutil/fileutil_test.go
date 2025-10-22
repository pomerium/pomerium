package fileutil

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsReadableFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    string
		want    bool
		wantErr bool
	}{
		{"good file", "fileutil.go", true, false},
		{"file doesn't exist", "file-no-exist/nope", false, false},
		{"can't read dir", "./", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsReadableFile(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsReadableFile() error = %+v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsReadableFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetwd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want string
	}{
		{"most basic example", "internal/fileutil"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Getwd(); strings.Contains(tt.want, got) {
				t.Errorf("Getwd() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadFileUpTo(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	input := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	fname := path.Join(d, "test")
	require.NoError(t, os.WriteFile(fname, input, 0o600))

	for _, tc := range []struct {
		size        int
		expectError bool
	}{
		{len(input) - 1, true},
		{len(input), false},
		{len(input) + 1, false},
	} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			out, err := ReadFileUpTo(fname, int64(tc.size))
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.True(t, bytes.Equal(input, out))
		})
	}
}
