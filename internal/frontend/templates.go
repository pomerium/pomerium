//go:generate statik -src=./assets -include=*.svg,*.html,*.css,*.js -ns web

// Package frontend handles the generation, and instantiation of Pomerium's
// html templates.
package frontend

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/rakyll/statik/fs"

	_ "github.com/pomerium/pomerium/internal/frontend/statik" // load static assets
)

const statikNamespace = "web"

// NewTemplates loads pomerium's templates. Panics on failure.
func NewTemplates() (*template.Template, error) {
	statikFS, err := fs.NewWithNamespace(statikNamespace)
	if err != nil {
		return nil, fmt.Errorf("internal/frontend: error creating new file system: %w", err)
	}

	dataURLs := map[string]template.URL{}

	err = fs.Walk(statikFS, "/", func(filePath string, fileInfo os.FileInfo, _ error) error {
		if fileInfo.IsDir() {
			return nil
		}

		file, err := statikFS.Open(filePath)
		if err != nil {
			return fmt.Errorf("internal/frontend: error opening %s: %w", filePath, err)
		}
		defer file.Close()

		bs, err := ioutil.ReadAll(file)
		if err != nil {
			return fmt.Errorf("internal/frontend: error reading %s: %w", filePath, err)
		}

		encoded := base64.StdEncoding.EncodeToString(bs)
		dataURLs[filePath] = template.URL(fmt.Sprintf(
			"data:%s;base64,%s", mime.TypeByExtension(path.Ext(filePath)), encoded))

		return nil
	})
	if err != nil {
		return nil, err
	}

	t := template.New("pomerium-templates").Funcs(map[string]interface{}{
		"dataURL": func(p string) template.URL {
			return dataURLs[strings.TrimPrefix(p, "/.pomerium/assets")]
		},
		"formatTime": func(tm time.Time) string {
			return tm.Format("2006-01-02 15:04:05 MST")
		},
	})

	err = fs.Walk(statikFS, "/html", func(filePath string, fileInfo os.FileInfo, err error) error {
		if !fileInfo.IsDir() {
			file, err := statikFS.Open(filePath)
			if err != nil {
				return fmt.Errorf("internal/frontend: error opening %s: %w", filePath, err)
			}

			buf, err := ioutil.ReadAll(file)
			if err != nil {
				return fmt.Errorf("internal/frontend: error reading %s: %w", filePath, err)
			}
			_, err = t.Parse(string(buf))
			if err != nil {
				return fmt.Errorf("internal/frontend: error parsing template %s: %w", filePath, err)
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
	statikFS, err := fs.NewWithNamespace(statikNamespace)
	if err != nil {
		panic(err)
	}
	return http.FileServer(statikFS)
}
