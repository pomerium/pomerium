package fileutil

import (
	"strings"
	"testing"
)

func TestIsReadableFile(t *testing.T) {
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
