package bootstrap

/*
 * in order to be able to start up pomerium in case cloud is unreachable,
 * we store the minimum bootstrap configuration (essentially, the data broker connection)
 * in a file. this file is encrypted with a key that is derived from the cluster token.
 *
 * this information should be sufficient for pomerium to locate the database and start up.
 *
 */
import (
	"context"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pomerium/pomerium/internal/zero/bootstrap/writers"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/health"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
)

// LoadBootstrapConfigFromFile loads the bootstrap configuration from a file.
func LoadBootstrapConfigFromFile(fp string, cipher cipher.AEAD) (*cluster_api.BootstrapConfig, error) {
	ciphertext, err := os.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap config: %w", err)
	}
	plaintext, err := cryptutil.Decrypt(cipher, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt bootstrap config: %w", err)
	}

	var dst cluster_api.BootstrapConfig
	err = json.Unmarshal(plaintext, &dst)
	if err != nil {
		return nil, fmt.Errorf("unmarshal bootstrap config: %w", err)
	}

	return &dst, nil
}

// SaveBootstrapConfig saves the bootstrap configuration to a file.
func SaveBootstrapConfig(ctx context.Context, writer writers.ConfigWriter, src *cluster_api.BootstrapConfig) error {
	err := writer.WriteConfig(ctx, src)
	if err != nil {
		health.ReportError(health.ZeroBootstrapConfigSave, err)
	} else {
		health.ReportRunning(health.ZeroBootstrapConfigSave)
	}
	return err
}
