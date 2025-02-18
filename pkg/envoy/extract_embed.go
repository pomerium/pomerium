//go:build !debug_local_envoy

package envoy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pomerium/pomerium/pkg/envoy/files"
)

func extract(dstName string) (err error) {
	checksum, err := hex.DecodeString(strings.Fields(files.Checksum())[0])
	if err != nil {
		return fmt.Errorf("checksum %s: %w", files.Checksum(), err)
	}

	hr := &hashReader{
		Hash: sha256.New(),
		r:    bytes.NewReader(files.Binary()),
	}

	dst, err := os.OpenFile(dstName, os.O_CREATE|os.O_WRONLY, ownerRX)
	if err != nil {
		return err
	}
	defer func() { err = dst.Close() }()

	if _, err = io.Copy(dst, io.LimitReader(hr, maxExpandedEnvoySize)); err != nil {
		return err
	}

	sum := hr.Sum(nil)
	if !bytes.Equal(sum, checksum) {
		return fmt.Errorf("expected %x, got %x checksum", checksum, sum)
	}
	return nil
}
