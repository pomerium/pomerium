package oidcprovider

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"
)

type JSONErrorResponse struct {
	Status      int    `json:"-"`
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *JSONErrorResponse) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")

	bs, err := json.Marshal(e)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("JSONErrorResponse: couldn't marshal JSON")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
		return
	}

	w.WriteHeader(e.Status)
	_, _ = w.Write(bs)
}
