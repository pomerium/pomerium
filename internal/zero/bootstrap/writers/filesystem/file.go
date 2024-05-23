package filesystem

import (
	"context"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/pomerium/pomerium/internal/zero/bootstrap/writers"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
)

func init() {
	writers.RegisterBuilder("file", func(uri *url.URL) (writers.ConfigWriter, error) {
		if uri.Host != "" {
			// prevent the common mistake of "file://path/to/file"
			return nil, fmt.Errorf(`invalid file uri %q (did you mean "file:///%s%s"?)`, uri.String(), uri.Host, uri.Path)
		}
		return &fileWriter{
			filePath: uri.Path,
		}, nil
	})
}

type fileWriter struct {
	filePath string
}

// WriteConfig implements ConfigWriter.
func (w *fileWriter) WriteConfig(_ context.Context, src *cluster_api.BootstrapConfig, cipher cipher.AEAD) error {
	plaintext, err := json.Marshal(src)
	if err != nil {
		return fmt.Errorf("marshal file config: %w", err)
	}

	ciphertext := cryptutil.Encrypt(cipher, plaintext, nil)
	err = os.WriteFile(w.filePath, ciphertext, 0o600)
	if err != nil {
		return fmt.Errorf("write bootstrap config: %w", err)
	}
	return nil
}

var _ writers.ConfigWriter = (*fileWriter)(nil)
