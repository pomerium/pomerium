package oidcprovider

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pomerium/pomerium/ui"
)

type HTMLErrorResponse struct {
	Status      int
	Description string
}

func (e *HTMLErrorResponse) serve(w http.ResponseWriter, r *http.Request) {
	statusText := http.StatusText(e.Status)
	m := map[string]any{
		"status":      e.Status,
		"statusText":  statusText,
		"description": e.Description,
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(e.Status)
	title := fmt.Sprintf("%d %s", e.Status, statusText)
	if err := ui.ServePage(w, r, "Error", title, m); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type JSONErrorResponse struct {
	Status      int    `json:"-"`
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *JSONErrorResponse) serve(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")

	bs, err := json.Marshal(e)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
		return
	}

	w.WriteHeader(e.Status)
	_, _ = w.Write(bs)
}
