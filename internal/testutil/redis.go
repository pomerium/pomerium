package testutil

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/ory/dockertest/v3"
)

const maxWait = time.Minute

// WithTestRedis creates a test a test redis instance using docker.
func WithTestRedis(handler func(rawURL string) error) error {
	ctx, clearTimeout := context.WithTimeout(context.Background(), maxWait)
	defer clearTimeout()

	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		return err
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "redis",
		Tag:        "6",
	})
	if err != nil {
		return err
	}
	_ = resource.Expire(uint(maxWait.Seconds()))

	redisURL := fmt.Sprintf("redis://%s/0", resource.GetHostPort("6379/tcp"))
	if err := pool.Retry(func() error {
		options, err := redis.ParseURL(redisURL)
		if err != nil {
			return err
		}

		client := redis.NewClient(options)
		defer client.Close()

		return client.Ping(ctx).Err()
	}); err != nil {
		_ = pool.Purge(resource)
		return err
	}

	e := handler(redisURL)

	if err := pool.Purge(resource); err != nil {
		return err
	}

	return e
}
