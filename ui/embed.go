// Package ui contains the user info dashboard ui.
package ui

import (
	"bytes"
	"html/template"
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
func ServePage(w http.ResponseWriter, r *http.Request, page, title string, data map[string]interface{}) error {
	if data == nil {
		data = make(map[string]any)
	}
	data["csrfToken"] = csrf.Token(r)
	data["page"] = page

	bs, err := renderTemplate("dist/index.gohtml", map[string]any{
		"Title": title,
		"Data":  data,
	})
	if err != nil {
		return err
	}

	http.ServeContent(w, r, "index.html", time.Now(), bytes.NewReader(bs))
	return nil
}

var startTime = time.Now()

func renderTemplate(name string, data any) ([]byte, error) {
	f, _, err := openFile(name)
	if err != nil {
		return nil, err
	}
	bs, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}

	tpl, err := template.New("").Parse(string(bs))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = tpl.Execute(&buf, data)
	return buf.Bytes(), err
}
