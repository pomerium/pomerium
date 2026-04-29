package scenarios

import (
	"context"
	"encoding/base64"
	"encoding/pem"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func DownstreamMTLS(mode configpb.MtlsEnforcementMode) testenv.Modifier {
	return testenv.ModifierFunc(func(ctx context.Context, cfg *config.Config) {
		env := testenv.EnvFromContext(ctx)
		block := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: env.CACert().Leaf.Raw,
		}
		cfg.Options.DownstreamMTLS = config.DownstreamMTLSSettings{
			CA:          base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&block)),
			Enforcement: nullable.From(mode),
		}
	})
}
