// Package ui contains the user info dashboard ui.
package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pomerium/csrf"
	"github.com/pomerium/pomerium/internal/urlutil"
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

	re, err := regexp.Compile(`(src|href)="(.*?)"`)
	if err != nil {
		return err
	}

	bs = re.ReplaceAllFunc(bs, func(b []byte) []byte {
		parts := re.FindStringSubmatch(string(b))
		if len(parts) < 3 {
			return b
		}
		return []byte(parts[1] + `="` + embedRelativeFileURL(parts[2]) + `"`)
	})

	bs = bytes.Replace(bs,
		[]byte("window.POMERIUM_DATA = {}"),
		append([]byte("window.POMERIUM_DATA = "), jsonData...),
		1)

	http.ServeContent(w, r, "index.html", time.Now(), bytes.NewReader(bs))
	return nil
}

var startTime = time.Now()

func embedRelativeFileURL(rawURL string) (dataURLOrOriginalURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	filePath := strings.Replace(u.Path, "/.pomerium/", "dist/", 1)
	f, _, err := openFile(filePath)
	if err != nil {
		return rawURL
	}
	bs, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return rawURL
	}

	mediaType := mime.TypeByExtension(path.Ext(rawURL))
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	if idx := strings.Index(mediaType, ";"); idx >= 0 {
		mediaType = mediaType[:idx]
	}
	return urlutil.DataURL(mediaType, bs)
}
