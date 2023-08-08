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

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func LoadBootstrapConfigFromFile(dst *config.Options, fp string, cipher cipher.AEAD) error {
	ciphertext, err := os.ReadFile(fp)
	if err != nil {
		return fmt.Errorf("read bootstrap config: %w", err)
	}
	plaintext, err := cryptutil.Decrypt(cipher, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypt bootstrap config: %w", err)
	}

	fc := fileConfig{}
	err = json.Unmarshal(plaintext, &fc)
	if err != nil {
		return fmt.Errorf("unmarshal bootstrap config: %w", err)
	}

	applyFileConfig(dst, fc)

	return nil
}

func SaveBootstrapConfigToFile(src *config.Options, fp string, cipher cipher.AEAD) error {
	plaintext, err := json.Marshal(getFileConfig(src))
	if err != nil {
		return fmt.Errorf("marshal file config: %w", err)
	}

	ciphertext := cryptutil.Encrypt(cipher, plaintext, nil)
	err = os.WriteFile(fp, ciphertext, 0600)
	if err != nil {
		return fmt.Errorf("write bootstrap config: %w", err)
	}
	return nil
}

type fileConfig struct {
	PostgresDSN *string `json:"postgres_dsn"`
}

func getFileConfig(src *config.Options) fileConfig {
	fc := fileConfig{}
	if src.DataBrokerStorageConnectionString != "" {
		fc.PostgresDSN = &src.DataBrokerStorageConnectionString
	}
	return fc
}

func applyFileConfig(dst *config.Options, fc fileConfig) {
	if fc.PostgresDSN != nil {
		dst.DataBrokerStorageConnectionString = *fc.PostgresDSN
	}
}
