package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/bufbuild/protovalidate-go"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/internal/log"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
)

const maxClientRegistrationPayload = 1024 * 1024 // 1MB

// RegisterClient handles the /register endpoint.
// It is used to register a new client with the MCP server.
func (srv *Handler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != http.MethodPost {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	src := io.LimitReader(r.Body, maxClientRegistrationPayload)
	defer r.Body.Close()

	data, err := io.ReadAll(src)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to read request body")
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	v := new(rfc7591v1.ClientMetadata)
	err = protojson.Unmarshal(data, v)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to unmarshal request body")
		http.Error(w, "failed to unmarshal request body", http.StatusBadRequest)
		return
	}

	err = protovalidate.Validate(v)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to validate request body")
		clientRegistrationBadRequest(w, err)
		return
	}

	id, err := srv.storage.RegisterClient(ctx, v)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to register client")
		http.Error(w, "failed to register client", http.StatusInternalServerError)
	}

	resp := struct {
		*rfc7591v1.ClientMetadata
		ClientID         string `json:"client_id"`
		ClientIDIssuedAt int64  `json:"client_id_issued_at"`
	}{
		ClientMetadata:   v,
		ClientID:         id,
		ClientIDIssuedAt: time.Now().Unix(),
	}
	data, err = json.Marshal(resp)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to marshal response")
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(data)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to write response")
		return
	}
}

func clientRegistrationBadRequest(w http.ResponseWriter, err error) {
	v := struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}{
		Error:            "invalid_client_metadata",
		ErrorDescription: err.Error(),
	}
	data, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(data)
}
