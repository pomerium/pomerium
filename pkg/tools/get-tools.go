package main

import (
	"context"
	"os"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/tools/golangcilint"
)

func main() {
	ctx := context.Background()
	if err := golangcilint.InstallLinter(ctx); err != nil {
		log.Ctx(ctx).Err(err).Msg("failed to download linter")
		os.Exit(1)
	}
}
