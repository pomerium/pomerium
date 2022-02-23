// Package directory contains protobuf types for directory users.
package directory

import (
	context "context"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// GetGroup gets a directory group from the databroker.
func GetGroup(ctx context.Context, client databroker.DataBrokerServiceClient, groupID string) (*Group, error) {
	g := Group{Id: groupID}
	return &g, databroker.Get(ctx, client, &g)
}

// GetUser gets a directory user from the databroker.
func GetUser(ctx context.Context, client databroker.DataBrokerServiceClient, userID string) (*User, error) {
	u := User{Id: userID}
	return &u, databroker.Get(ctx, client, &u)
}

// Options are directory provider options.
type Options struct {
	ServiceAccount string
	Provider       string
	ProviderURL    string
	ClientID       string
	ClientSecret   string
	QPS            float64
}
