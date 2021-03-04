// Package frontend handles the generation, and instantiation of Pomerium's
// html templates.
package frontend

import (
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// FS is the frontend assets file system.
//go:embed assets
var FS embed.FS

// NewTemplates loads pomerium's templates. Panics on failure.
func NewTemplates() (*template.Template, error) {
	assetsFS, err := fs.Sub(FS, "assets")
	if err != nil {
		return nil, err
	}

	dataURLs := map[string]template.URL{}
	err = fs.WalkDir(assetsFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		bs, err := fs.ReadFile(assetsFS, p)
		if err != nil {
			return fmt.Errorf("internal/frontend: error reading %s: %w", p, err)
		}

		encoded := base64.StdEncoding.EncodeToString(bs)
		dataURLs[p] = template.URL(fmt.Sprintf(
			"data:%s;base64,%s", mime.TypeByExtension(path.Ext(p)), encoded))

		return nil
	})
	if err != nil {
		return nil, err
	}

	t := template.New("pomerium-templates").Funcs(map[string]interface{}{
		"safeURL": func(arg interface{}) template.URL {
			return template.URL(fmt.Sprint(arg))
		},
		"safeHTML": func(arg interface{}) template.HTML {
			return template.HTML(fmt.Sprint(arg))
		},
		"safeHTMLAttr": func(arg interface{}) template.HTMLAttr {
			return template.HTMLAttr(fmt.Sprint(arg))
		},
		"dataURL": func(p string) template.URL {
			return dataURLs[strings.TrimPrefix(p, "/.pomerium/assets/")]
		},
		"formatTime": func(tm time.Time) string {
			return tm.Format("2006-01-02 15:04:05 MST")
		},
	})

	err = fs.WalkDir(assetsFS, "html", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			bs, err := fs.ReadFile(assetsFS, p)
			if err != nil {
				return fmt.Errorf("internal/frontend: error reading %s: %w", p, err)
			}

			_, err = t.Parse(string(bs))
			if err != nil {
				return fmt.Errorf("internal/frontend: error parsing template %s: %w", p, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return t, nil
}

// MustAssetHandler wraps a call to the embedded static file system and panics
// if the error is non-nil. It is intended for use in variable initializations
func MustAssetHandler() http.Handler {
	assetsFS, err := fs.Sub(FS, "assets")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(assetsFS))
}
