package configapi

import (
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

func benchConfig100Routes() *configpb.Config {
	routes := make([]*configpb.Route, 100)
	for i := range routes {
		routes[i] = &configpb.Route{
			To: []string{"https://user:password@upstream.example.com/path"},
			Mcp: &configpb.MCP{Mode: &configpb.MCP_Server{Server: &configpb.MCPServer{
				UpstreamOauth2: &configpb.UpstreamOAuth2{ClientSecret: "benchmark-oauth2-client-secret"},
			}}},
		}
	}
	return &configpb.Config{Routes: routes}
}

func benchAnyDepth16() *anypb.Any {
	var msg proto.Message = sensitiveConfig("benchmark-depth-secret")
	for range maxSensitiveAnyDepth {
		var err error
		msg, err = anypb.New(msg)
		if err != nil {
			panic(err)
		}
	}
	return msg.(*anypb.Any)
}

// benchAnyNear5MiBCap builds a single Any whose Value sits just under the
// cumulative byte cap — the worst case the budget check still has to
// unmarshal, scrub, and repack.
func benchAnyNear5MiBCap() *anypb.Any {
	largeName := strings.Repeat("x", maxSensitiveAnyBytes-1024)
	cfg := sensitiveConfig("benchmark-near-cap-secret")
	cfg.Routes[0].Name = &largeName
	a, err := anypb.New(cfg)
	if err != nil {
		panic(err)
	}
	return a
}

func benchRegisterRequest1000Entries() *registrypb.RegisterRequest {
	metadata := make(map[string]*anypb.Any, 1000)
	for i := range 1000 {
		a, err := anypb.New(sensitiveConfig("benchmark-map-entry-secret"))
		if err != nil {
			panic(err)
		}
		metadata[strconv.Itoa(i)] = a
	}
	return &registrypb.RegisterRequest{Metadata: metadata}
}

func BenchmarkScrubSensitive(b *testing.B) {
	b.Run("config-100-routes", func(b *testing.B) {
		b.ReportAllocs()
		base := benchConfig100Routes()
		clones := make([]*configpb.Config, b.N)
		for i := range clones {
			clones[i] = proto.Clone(base).(*configpb.Config)
		}
		b.ResetTimer()
		for i := range b.N {
			ScrubSensitive(clones[i])
		}
	})

	b.Run("any-depth-16", func(b *testing.B) {
		b.ReportAllocs()
		base := benchAnyDepth16()
		clones := make([]*anypb.Any, b.N)
		for i := range clones {
			clones[i] = proto.Clone(base).(*anypb.Any)
		}
		b.ResetTimer()
		for i := range b.N {
			ScrubSensitive(clones[i])
		}
	})

	b.Run("any-near-5mib-cap", func(b *testing.B) {
		// Clone per iteration outside the timer: pre-building b.N multi-MiB
		// clones would balloon memory, and timing the clone would dominate.
		b.ReportAllocs()
		base := benchAnyNear5MiBCap()
		for range b.N {
			b.StopTimer()
			clone := proto.Clone(base).(*anypb.Any)
			b.StartTimer()
			ScrubSensitive(clone)
		}
	})

	b.Run("map-1000-entries", func(b *testing.B) {
		b.ReportAllocs()
		base := benchRegisterRequest1000Entries()
		clones := make([]*registrypb.RegisterRequest, b.N)
		for i := range clones {
			clones[i] = proto.Clone(base).(*registrypb.RegisterRequest)
		}
		b.ResetTimer()
		for i := range b.N {
			ScrubSensitive(clones[i])
		}
	})
}

func BenchmarkSensitiveFieldsSet(b *testing.B) {
	b.Run("config-100-routes", func(b *testing.B) {
		b.ReportAllocs()
		cfg := benchConfig100Routes()
		b.ResetTimer()
		for range b.N {
			SensitiveFieldsSet(cfg)
		}
	})
}
