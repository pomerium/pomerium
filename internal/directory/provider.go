// Package directory implements the user group directory service.
package directory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/directory/onelogin"
	"github.com/pomerium/pomerium/internal/grpc/directory"
	"github.com/pomerium/pomerium/internal/log"
)

// A User is a directory User.
type User = directory.User

// A Provider provides user group directory information.
type Provider interface {
	UserGroups(ctx context.Context) ([]*User, error)
}

// GetProvider gets the provider for the given options.
func GetProvider(options *config.Options) Provider {
	switch options.Provider {
	case "onelogin":
		creds, err := getOneLoginCredentials(options.ServiceAccount)
		if err == nil {
			return onelogin.New(onelogin.WithCredentials(creds.ClientID, creds.ClientSecret))
		}

		log.Warn().
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for onelogin directory provider")
	}

	log.Warn().
		Str("provider", options.Provider).
		Msg("no directory provider implementation found, disabling support for groups")
	return nullProvider{}
}

type nullProvider struct{}

func (nullProvider) UserGroups(ctx context.Context) ([]*User, error) {
	return nil, nil
}

type oneLoginCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func getOneLoginCredentials(serviceAcount string) (*oneLoginCredentials, error) {
	bs, err := base64.StdEncoding.DecodeString(serviceAcount)
	if err != nil {
		return nil, err
	}

	var creds oneLoginCredentials
	err = json.Unmarshal(bs, &creds)
	if err != nil {
		return nil, err
	}

	if creds.ClientID == "" {
		return nil, fmt.Errorf("onelogin: client_id is required in service account")
	}
	if creds.ClientSecret == "" {
		return nil, fmt.Errorf("onelogin: client_secret is required in service account")
	}

	return &creds, nil
}
