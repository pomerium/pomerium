package filesystem

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/pomerium/pomerium/internal/zero/bootstrap/writers"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
)

func init() {
	writers.RegisterBuilder("file", newFileWriter)
}

func newFileWriter(uri *url.URL) (writers.ConfigWriter, error) {
	if uri.Host != "" {
		// prevent the common mistake of "file://path/to/file"
		return nil, fmt.Errorf(`invalid file uri %q (did you mean "file:///%s%s"?)`, uri.String(), uri.Host, uri.Path)
	}
	return &fileWriter{
		filePath: uri.Path,
	}, nil
}

type fileWriter struct {
	opts     writers.ConfigWriterOptions
	filePath string
}

// WithOptions implements writers.ConfigWriter.
func (w *fileWriter) WithOptions(opts writers.ConfigWriterOptions) writers.ConfigWriter {
	clone := *w
	clone.opts = opts
	return &clone
}

// WriteConfig implements ConfigWriter.
func (w *fileWriter) WriteConfig(_ context.Context, src *cluster_api.BootstrapConfig) error {
	data, err := json.Marshal(src)
	if err != nil {
		return fmt.Errorf("marshal file config: %w", err)
	}

	if w.opts.Cipher != nil {
		data = cryptutil.Encrypt(w.opts.Cipher, data, nil)
	}
	err = os.WriteFile(w.filePath, data, 0o600)
	if err != nil {
		return fmt.Errorf("write bootstrap config: %w", err)
	}
	return nil
}

var _ writers.ConfigWriter = (*fileWriter)(nil)
