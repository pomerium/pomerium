//go:build !debug_local_envoy

package envoy

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"github.com/cespare/xxhash/v2"
	"github.com/zeebo/xxh3"

	"github.com/pomerium/pomerium/pkg/envoy/files"
)

func extract(dstName string) error {
	lockfile := files.Lockfile()
	digestStr := lockfile.Digest
	alg, digest, ok := strings.Cut(digestStr, ":")
	if !ok {
		return fmt.Errorf("invalid digest format: expecting 'algorithm:digest'")
	}
	var hash hash.Hash
	switch alg {
	case "sha256":
		hash = sha256.New()
	case "xxh3":
		hash = xxh3.New()
	case "xxh64":
		hash = xxhash.New()
	}
	hr := &hashReader{
		Hash: hash,
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

	actual := fmt.Sprintf("%x", hr.Sum(nil))
	if actual != digest {
		return fmt.Errorf("expected %s, got %s checksum", digest, actual)
	}
	return nil
}
