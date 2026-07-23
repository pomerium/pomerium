package cmd

import (
	"context"

	"github.com/pomerium/pomerium/internal/zero/cmd"
)

func Run(ctx context.Context, token string) error {
	return cmd.RunWithToken(ctx, token)
}
