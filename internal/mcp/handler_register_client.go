package mcp

import (
	"io"
	"net/http"

	"github.com/bufbuild/protovalidate-go"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

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

	v := new(rfc7591v1.ClientRegistrationRequest)
	err = protojson.Unmarshal(data, v)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to unmarshal request body")
		http.Error(w, "failed to unmarshal request body", http.StatusBadRequest)
		return
	}

	err = protovalidate.Validate(v)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to validate request body")
		clientRegistrationError(w, err, rfc7591v1.ErrorCode_ERROR_CODE_INVALID_CLIENT_METADATA)
		return
	}

	resp, err := srv.storage.RegisterClient(ctx, v)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to register client")
		http.Error(w, "failed to register client", http.StatusInternalServerError)
	}

	data, err = protojson.MarshalOptions{
		UseProtoNames: true,
	}.Marshal(resp)
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

func clientRegistrationError(w http.ResponseWriter, err error, code rfc7591v1.ErrorCode) {
	v := &rfc7591v1.ClientRegistrationErrorResponse{
		Error:            code,
		ErrorDescription: proto.String(err.Error()),
	}
	data, _ := protojson.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(data)
}
