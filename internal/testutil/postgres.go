package testutil

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/ory/dockertest/v3"

	"github.com/pomerium/pomerium/internal/log"
)

// WithTestPostgres starts a test DB and runs the given handler with the connection to it.
func WithTestPostgres(handler func(dsn string) error) error {
	ctx, clearTimeout := context.WithTimeout(context.Background(), maxWait)
	defer clearTimeout()

	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		return err
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "14",
		Env:        []string{"POSTGRES_DB=pomeriumtest", "POSTGRES_HOST_AUTH_METHOD=trust"},
	})
	if err != nil {
		return err
	}
	_ = resource.Expire(uint(maxWait.Seconds()))

	dsn := fmt.Sprintf("postgresql://postgres@localhost:%s/pomeriumtest?sslmode=disable", resource.GetPort("5432/tcp"))
	if err := pool.Retry(func() error {
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Send()
			return err
		}
		_ = conn.Close(ctx)
		return nil
	}); err != nil {
		_ = pool.Purge(resource)
		return err
	}

	e := handler(dsn)

	if err := pool.Purge(resource); err != nil {
		return err
	}

	return e
}
