package envoyconfig

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"os"
	"strings"

	"github.com/pomerium/pomerium/internal/log"
)

// ReadDynamicExtensionID reads the extension ID embedded in the .dx_metadata
// ELF section of a pomerium-envoy dynamic extension shared object
func ReadDynamicExtensionID(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("error reading extension %s: %w", path, err)
	}
	defer f.Close()
	ef, err := elf.NewFile(f)
	if err != nil {
		return "", fmt.Errorf("error reading extension %s: %w", path, err)
	}
	defer ef.Close()

	section := ef.Section(".dx_metadata")
	if section == nil {
		return "", fmt.Errorf("extension is missing metadata: %s", path)
	}
	data, err := section.Data()
	if err != nil {
		return "", fmt.Errorf("error reading metadata for extension %s: %w", path, err)
	}
	for kv := range bytes.SplitSeq(data, []byte{0}) {
		if len(kv) == 0 {
			continue
		}
		k, v, ok := strings.Cut(string(kv), "=")
		if !ok {
			return "", fmt.Errorf("error reading metadata for extension %s: invalid format", path)
		}
		if k == "id" {
			log.Ctx(ctx).Debug().Str("path", path).Str("id", v).Msg("found extension id")
			return v, nil
		}
	}
	return "", fmt.Errorf("could not find id in extension metadata: %s", path)
}
