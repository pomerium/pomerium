// Package ui contains the user info dashboard ui.
package ui

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pomerium/csrf"
)

var (
	//go:embed dist/*
	uiFS embed.FS
)

// ServeFile serves a file.
func ServeFile(w http.ResponseWriter, r *http.Request, filePath string) error {
	f, etag, err := openLocalOrEmbeddedFile(filepath.Join("dist", filePath))
	if err != nil {
		return err
	}
	defer f.Close()

	w.Header().Set("ETag", `"`+etag+`"`)
	http.ServeContent(w, r, filepath.Base(filePath), time.Time{}, f.(io.ReadSeeker))
	return nil
}

// ServePage serves the index.html page.
func ServePage(w http.ResponseWriter, r *http.Request, page string, data map[string]interface{}) error {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["csrfToken"] = csrf.Token(r)
	data["page"] = page

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	f, _, err := openLocalOrEmbeddedFile("dist/index.html")
	if err != nil {
		return err
	}
	bs, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return err
	}

	bs = bytes.Replace(bs,
		[]byte("window.POMERIUM_DATA = {}"),
		append([]byte("window.POMERIUM_DATA = "), jsonData...),
		1)

	http.ServeContent(w, r, "index.html", time.Now(), bytes.NewReader(bs))
	return nil
}

var startTime = time.Now()

func openLocalOrEmbeddedFile(name string) (f fs.File, etag string, err error) {
	f, err = os.Open(filepath.Join("ui", name))
	if os.IsNotExist(err) {
		f, err = uiFS.Open(name)
	}
	if err != nil {
		return nil, "", err
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, "", err
	}

	modTime := fi.ModTime()
	if modTime.IsZero() {
		modTime = startTime
	}
	etag = fmt.Sprintf("%x", modTime.UnixNano())

	return f, etag, nil
}
