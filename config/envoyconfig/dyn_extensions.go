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
func ReadDynamicExtensionID(ctx context.Context, path string) (id string, envoySha string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("error reading extension %s: %w", path, err)
	}
	defer f.Close()
	ef, err := elf.NewFile(f)
	if err != nil {
		return "", "", fmt.Errorf("error reading extension %s: %w", path, err)
	}
	defer ef.Close()

	sha, err := tryResolveEnvoyShaFromExtension(ef)
	if err != nil {
		// we specifically don't enforce strict sha matching from the go-side. Envoy handles this.
		// It is useful for potentially selecting which extension is the most compatible, if multiple
		// config sources hand the same extension (by ID) to Pomerium on different file paths.
		log.Ctx(ctx).Warn().Str("ext-path", path).Msg("failed to determine envoy sha version")
	}

	extID, err := tryResolveEnvoyExtID(ef)
	if err != nil {
		log.Ctx(ctx).Err(err).Str("ext-path", path).Msg("failed to determined envoy extension ID")
		return "", "", err
	}
	return extID, sha, nil
}

func tryResolveEnvoyExtID(ef *elf.File) (id string, err error) {
	section := ef.Section(".dx_metadata")
	if section == nil {
		return "", fmt.Errorf("extension is missing metadata")
	}
	data, err := section.Data()
	if err != nil {
		return "", fmt.Errorf("error reading metadata for extension: %w", err)
	}
	for kv := range bytes.SplitSeq(data, []byte{0}) {
		if len(kv) == 0 {
			continue
		}
		k, v, ok := strings.Cut(string(kv), "=")
		if !ok {
			return "", fmt.Errorf("error reading metadata for extension: invalid format")
		}
		if k == "id" {
			return v, nil
		}
	}
	return "", fmt.Errorf("could not find id in extension metadata")
}

const (
	symEnvoyVersionPrefix = "pomerium_envoy_version_"
)

func tryResolveEnvoyShaFromExtension(ef *elf.File) (sha string, err error) {
	syms, err := ef.DynamicSymbols()
	if err != nil {
		return "", err
	}
	for _, s := range syms {
		if s.Section != elf.SHN_UNDEF {
			continue
		}
		if sha, ok := strings.CutPrefix(s.Name, symEnvoyVersionPrefix); ok {
			return sha, nil
		}
	}
	return "", fmt.Errorf("no %s symbol found", symEnvoyVersionPrefix)
}
