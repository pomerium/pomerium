//go:build !debug_local_envoy

package envoy

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"
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
		// Ignore digest mismatch if started from testenv so that integration tests
		// can be run using development versions of envoy by replacing the binary.
		//
		// TODO: starting in go 1.27, debug.BuildInfo for test binaries will have
		// module deps populated which can be used to check if envoy-custom is
		// replaced. Then the replacement path can be used in a similar way as
		// setting the debug_local_envoy build tag and extracting the embedded
		// binary can be skipped entirely.
		callers := make([]uintptr, 8)
		n := runtime.Callers(2, callers)
		frames := runtime.CallersFrames(callers[:n])
		for {
			frame, more := frames.Next()
			// the actual caller is an anonymous function inside Start (i.e. '.Start.func#')
			if strings.HasPrefix(frame.Function,
				"github.com/pomerium/pomerium/internal/testenv.(*environment).Start") {
				fmt.Fprintf(os.Stderr, "WARNING: envoy digest mismatch ignored in test environment\n")
				return nil
			}
			if !more {
				break
			}
		}

		return fmt.Errorf("expected %s, got %s checksum", digest, actual)
	}
	return nil
}
