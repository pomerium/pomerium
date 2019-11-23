//go:generate statik -src=./assets -include=*.svg,*.html,*.css,*.js

package frontend // import "github.com/pomerium/pomerium/internal/frontend"

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/rakyll/statik/fs"

	_ "github.com/pomerium/pomerium/internal/frontend/statik" // load static assets
)

// NewTemplates loads pomerium's templates. Panics on failure.
func NewTemplates() (*template.Template, error) {
	t := template.New("pomerium-templates")
	statikFS, err := fs.New()
	if err != nil {
		return nil, fmt.Errorf("internal/frontend: error creating new file system: %w", err)
	}

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
			t.Parse(string(buf))
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
	statikFS, err := fs.New()
	if err != nil {
		panic(err)
	}
	return http.FileServer(statikFS)
}
