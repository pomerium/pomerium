package metrics

import (
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

// The following tags are applied to stats recorded by this package.
var (
	TagKeyHTTPMethod  = tag.MustNewKey("http_method")
	TagKeyService     = tag.MustNewKey("service")
	TagConfigID       = tag.MustNewKey("config_id")
	TagKeyGRPCService = tag.MustNewKey("grpc_service")
	TagKeyGRPCMethod  = tag.MustNewKey("grpc_method")
	TagKeyHost        = tag.MustNewKey("host")

	TagKeyStorageOperation = tag.MustNewKey("operation")
	TagKeyStorageResult    = tag.MustNewKey("result")
	TagKeyStorageBackend   = tag.MustNewKey("backend")

	TagKeyCgroup     = tag.MustNewKey("cgroup")
	TagKeyActionName = tag.MustNewKey("action_name")
)

// Default distributions used by views in this package.
var (
	DefaulHTTPSizeDistribution = view.Distribution(
		1, 256, 512, 1024, 2048, 8192, 16384, 32768, 65536, 131072, 262144,
		524288, 1048576, 2097152, 4194304, 8388608)
	DefaultHTTPLatencyDistrubtion = view.Distribution(
		1, 2, 5, 7, 10, 25, 500, 750, 100, 250, 500, 750, 1000, 2500, 5000,
		7500, 10000, 25000, 50000, 75000, 100000)
	grpcSizeDistribution = view.Distribution(
		1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024,
		2048, 4096, 8192, 16384,
	)
	DefaultMillisecondsDistribution = ocgrpc.DefaultMillisecondsDistribution
)

// DefaultViews are a set of default views to view HTTP and GRPC metrics.
var (
	DefaultViews = [][]*view.View{
		GRPCClientViews,
		GRPCServerViews,
		HTTPClientViews,
		HTTPServerViews,
		InfoViews,
		EnvoyViews,
	}
)
