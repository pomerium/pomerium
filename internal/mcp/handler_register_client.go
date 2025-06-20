package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/cryptutil"
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

	clientRegistration, err := createClientRegistrationFromMetadata(data)
	if err != nil {
		log.Ctx(ctx).Error().
			Str("request", string(data)).
			Err(err).Msg("create client registration")
		clientRegistrationBadRequest(w, err)
		return
	}

	id, err := srv.storage.RegisterClient(ctx, clientRegistration)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to register client")
		http.Error(w, "failed to register client", http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	err = rfc7591v1.WriteRegistrationResponse(w, id,
		clientRegistration.ClientSecret, clientRegistration.ResponseMetadata)
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

func createClientRegistrationFromMetadata(
	requestMetadataText []byte,
) (*rfc7591v1.ClientRegistration, error) {
	requestMetadata, err := rfc7591v1.ParseMetadata(requestMetadataText)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	err = requestMetadata.Validate()
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	responseMetadata := proto.CloneOf(requestMetadata)
	responseMetadata.SetDefaults()

	registration := &rfc7591v1.ClientRegistration{
		RequestMetadata:  requestMetadata,
		ResponseMetadata: responseMetadata,
	}

	if requestMetadata.GetTokenEndpointAuthMethod() != rfc7591v1.TokenEndpointAuthMethodNone {
		registration.ClientSecret = &rfc7591v1.ClientSecret{
			Value:     cryptutil.NewRandomStringN(32),
			CreatedAt: timestamppb.Now(),
		}
	}

	return registration, nil
}
