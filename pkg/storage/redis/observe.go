package redis

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"

	pomeriumconfig "github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

type logger struct {
}

func (l logger) Printf(ctx context.Context, format string, v ...interface{}) {
	log.Info().Str("service", "redis").Msgf(format, v...)
}

func init() {
	redis.SetLogger(logger{})
}

func recordOperation(ctx context.Context, startTime time.Time, operation string, err error) {
	metrics.RecordStorageOperation(ctx, &metrics.StorageOperationTags{
		Operation: operation,
		Error:     err,
		Backend:   pomeriumconfig.StorageRedisName,
	}, time.Since(startTime))
}
