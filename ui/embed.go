// Package ui contains the user info dashboard ui.
package ui

import (
	"bytes"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"sync"
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

// RenderPage rends the index.html page.
func RenderPage(page, title string, data map[string]any) ([]byte, error) {
	if data == nil {
		data = make(map[string]any)
	}
	data["page"] = page

	return renderIndex(map[string]any{
		"Title": title,
		"Data":  data,
	})
}

// ServePage serves the index.html page.
func ServePage(w http.ResponseWriter, r *http.Request, statusCode int, page, title string, data map[string]any) error {
	if data == nil {
		data = make(map[string]any)
	}
	data["csrfToken"] = csrf.Token(r)

	bs, err := RenderPage(page, title, data)
	if err != nil {
		return err
	}

	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	_, _ = w.Write(bs)
	return nil
}

var startTime = time.Now()

func renderIndex(data any) ([]byte, error) {
	tpl, err := parseIndex()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = tpl.Execute(&buf, data)
	return buf.Bytes(), err
}

var (
	parseIndexOnce     sync.Once
	parseIndexTemplate *template.Template
	parseIndexError    error
)

func parseIndex() (*template.Template, error) {
	parseIndexOnce.Do(func() {
		var f fs.File
		f, _, parseIndexError = openFile("dist/index.gohtml")
		if parseIndexError != nil {
			return
		}
		var bs []byte
		bs, parseIndexError = io.ReadAll(f)
		_ = f.Close()
		if parseIndexError != nil {
			return
		}

		parseIndexTemplate, parseIndexError = template.New("").Parse(string(bs))
	})
	return parseIndexTemplate, parseIndexError
}
