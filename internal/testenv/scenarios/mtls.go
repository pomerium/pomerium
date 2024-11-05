package scenarios

import (
	"context"
	"encoding/base64"
	"encoding/pem"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
)

func DownstreamMTLS(mode config.MTLSEnforcement) testenv.Modifier {
	return testenv.ModifierFunc(func(ctx context.Context, cfg *config.Config) {
		env := testenv.EnvFromContext(ctx)
		block := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: env.CACert().Leaf.Raw,
		}
		cfg.Options.DownstreamMTLS = config.DownstreamMTLSSettings{
			CA:          base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&block)),
			Enforcement: mode,
		}
	})
}
