// +build redis

package databroker

import (
	"os"

	"github.com/pomerium/pomerium/pkg/storage/redis"
)

func newTestServer() *Server {
	address := "redis://localhost:6379/0"
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		address = redisURL
	}
	return New(WithStorageType(redis.Name), WithStorageConnectionString(address))
}
