package rfc7591v1

import (
	"encoding/json"
	"fmt"
	"io"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	TokenEndpointAuthMethodNone              = "none"
	TokenEndpointAuthMethodClientSecretBasic = "client_secret_basic"
	TokenEndpointAuthMethodClientSecretPost  = "client_secret_post"

	GrantTypesAuthorizationCode = "authorization_code"
	GrantTypesImplicit          = "implicit"
	GrantTypesPassword          = "password"
	GrantTypesClientCredentials = "client_credentials"
	GrantTypesRefreshToken      = "refresh_token"
	GrantTypesJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"   //nolint:gosec
	GrantTypesSAML2Bearer       = "urn:ietf:params:oauth:grant-type:saml2-bearer" //nolint:gosec
	GrantTypesDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"  //nolint:gosec

	ResponseTypesCode = "code"
	ResponseTypeToken = "token"
)

func (v *Metadata) SetDefaults() {
	if v.TokenEndpointAuthMethod == nil {
		v.TokenEndpointAuthMethod = proto.String(TokenEndpointAuthMethodClientSecretBasic)
	}

	if len(v.GrantTypes) == 0 {
		v.GrantTypes = []string{GrantTypesAuthorizationCode}
	}

	if len(v.ResponseTypes) == 0 {
		v.ResponseTypes = []string{ResponseTypesCode}
	}
}

func (v *Metadata) Validate() error {
	return protovalidate.Validate(v)
}

func ParseMetadata(
	data []byte,
) (*Metadata, error) {
	v := new(Metadata)
	err := protojson.UnmarshalOptions{
		AllowPartial:   false,
		DiscardUnknown: true,
	}.Unmarshal(data, v)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func WriteRegistrationResponse(
	w io.Writer,
	clientID string,
	clientSecret *ClientSecret,
	metadata *Metadata,
) error {
	var metadataJSON map[string]any
	if metadata == nil {
		return fmt.Errorf("metadata cannot be nil")
	}
	metadataBytes, err := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: false,
	}.Marshal(metadata)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(metadataBytes, &metadataJSON); err != nil {
		return err
	}

	metadataJSON["client_id"] = clientID

	if clientSecret != nil {
		metadataJSON["client_secret"] = clientSecret.Value
		if clientSecret.CreatedAt != nil {
			metadataJSON["client_id_issued_at"] = clientSecret.CreatedAt.Seconds
		}

		// Per RFC 7591: client_secret_expires_at is REQUIRED if client_secret is issued
		// Value should be 0 if the secret doesn't expire
		if clientSecret.ExpiresAt != nil {
			metadataJSON["client_secret_expires_at"] = clientSecret.ExpiresAt.Seconds
		} else {
			metadataJSON["client_secret_expires_at"] = int64(0)
		}
	}

	return json.NewEncoder(w).Encode(metadataJSON)
}
