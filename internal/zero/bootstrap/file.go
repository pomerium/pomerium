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
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pomerium/pomerium/pkg/cryptutil"
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

// SaveBootstrapConfigToFile saves the bootstrap configuration to a file.
func SaveBootstrapConfigToFile(src *cluster_api.BootstrapConfig, fp string, cipher cipher.AEAD) error {
	plaintext, err := json.Marshal(src)
	if err != nil {
		return fmt.Errorf("marshal file config: %w", err)
	}

	ciphertext := cryptutil.Encrypt(cipher, plaintext, nil)
	err = os.WriteFile(fp, ciphertext, 0o600)
	if err != nil {
		return fmt.Errorf("write bootstrap config: %w", err)
	}
	return nil
}
