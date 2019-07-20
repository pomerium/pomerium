package metrics

import (
	"go.opencensus.io/tag"
)

var (
	keyHTTPMethod  tag.Key = tag.MustNewKey("http_method")
	keyService     tag.Key = tag.MustNewKey("service")
	keyGRPCService tag.Key = tag.MustNewKey("grpc_service")
	keyGRPCMethod  tag.Key = tag.MustNewKey("grpc_method")
	keyHost        tag.Key = tag.MustNewKey("host")
	keyDestination tag.Key = tag.MustNewKey("destination")
)
