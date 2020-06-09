// Package directory implements the user group directory service.
package directory

import (
	"context"

	"github.com/pomerium/pomerium/internal/grpc/directory"
)

// A User is a directory User.
type User = directory.User

// A Provider provides user group directory information.
type Provider interface {
	UserGroups(ctx context.Context) ([]*User, error)
}
