package config_test

import (
	"io"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"google.golang.org/grpc/grpclog"
)

func BenchmarkStartupLatency(b *testing.B) {
	grpclog.SetLoggerV2(grpclog.NewLoggerV2WithVerbosity(io.Discard, io.Discard, io.Discard, 0))
	b.ReportAllocs()
	b.Run("50 routes", func(b *testing.B) {
		for range b.N {
			env := testenv.New(b)
			env.Add(snippets.TemplateRoutes(50, snippets.SimplePolicyTemplate))
			env.Start()

			d := snippets.WaitStartupComplete(b, env)
			b.ReportMetric(d.Seconds(), "sec/op")
			env.Stop()
		}
	})

	b.Run("500 routes", func(b *testing.B) {
		for range b.N {
			env := testenv.New(b)
			env.Add(snippets.TemplateRoutes(500, snippets.SimplePolicyTemplate))
			env.Start()

			d := snippets.WaitStartupComplete(b, env)
			b.ReportMetric(d.Seconds(), "sec/op")
			env.Stop()
		}
	})

	b.Run("5000 routes", func(b *testing.B) {
		for range b.N {
			env := testenv.New(b)
			env.Add(snippets.TemplateRoutes(5000, snippets.SimplePolicyTemplate))
			env.Start()

			d := snippets.WaitStartupComplete(b, env, 10*time.Minute)
			b.ReportMetric(d.Seconds(), "sec/op")
		}
	})
}
