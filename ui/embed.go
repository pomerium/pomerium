// Package ui contains the user info dashboard ui.
package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"github.com/pomerium/csrf"
)

// ServeFile serves a file.
func ServeFile(w http.ResponseWriter, r *http.Request, filePath string) error {
	f, etag, err := openFile(filepath.Join("dist", filePath))
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

	f, _, err := openFile("dist/index.html")
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
