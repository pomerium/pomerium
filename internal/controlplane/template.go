package controlplane

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"time"
)

//go:embed template.gohtml
var templateSource string

func (srv *debugServer) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	tpl, err := template.New("").Parse(templateSource)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	err = tpl.ExecuteTemplate(&buf, page, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	body := template.HTML(buf.String()) //nolint: gosec
	buf.Reset()

	err = tpl.ExecuteTemplate(&buf, "Layout", body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, page+".html", time.Now(), bytes.NewReader(buf.Bytes()))
}
