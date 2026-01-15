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

	log.Ctx(ctx).Debug().
		Str("method", r.Method).
		Str("host", r.Host).
		Str("path", r.URL.Path).
		Str("content-type", r.Header.Get("Content-Type")).
		Int64("content-length", r.ContentLength).
		Msg("mcp/register: request received")

	if r.Method != http.MethodPost {
		log.Ctx(ctx).Debug().Str("method", r.Method).Msg("mcp/register: rejecting non-POST method")
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	src := io.LimitReader(r.Body, maxClientRegistrationPayload)
	defer r.Body.Close()

	data, err := io.ReadAll(src)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/register: failed to read request body")
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	log.Ctx(ctx).Debug().
		Int("body-size", len(data)).
		Str("body", string(data)).
		Msg("mcp/register: received client registration request body")

	clientRegistration, err := createClientRegistrationFromMetadata(data)
	if err != nil {
		log.Ctx(ctx).Error().
			Str("request", string(data)).
			Err(err).Msg("mcp/register: failed to create client registration from metadata")
		clientRegistrationBadRequest(w, err)
		return
	}

	log.Ctx(ctx).Debug().
		Strs("redirect-uris", clientRegistration.ResponseMetadata.GetRedirectUris()).
		Str("token-endpoint-auth-method", clientRegistration.ResponseMetadata.GetTokenEndpointAuthMethod()).
		Strs("grant-types", clientRegistration.ResponseMetadata.GetGrantTypes()).
		Strs("response-types", clientRegistration.ResponseMetadata.GetResponseTypes()).
		Bool("has-client-secret", clientRegistration.ClientSecret != nil).
		Msg("mcp/register: client registration parsed successfully")

	id, err := srv.storage.RegisterClient(ctx, clientRegistration)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/register: failed to register client")
		http.Error(w, "failed to register client", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Info().
		Str("client-id", id).
		Msg("mcp/register: client registered successfully")

	w.Header().Set("Content-Type", "application/json")
	err = rfc7591v1.WriteRegistrationResponse(w, id,
		clientRegistration.ClientSecret, clientRegistration.ResponseMetadata)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/register: failed to write response")
		return
	}

	log.Ctx(ctx).Debug().
		Str("client-id", id).
		Msg("mcp/register: registration response sent")
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
