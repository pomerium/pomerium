package main

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/pflag"
	"github.com/zeebo/xxh3"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/pomerium/pomerium/pkg/envoy/envoyversion"
)

var debug bool

func main() {
	var outputDir string
	var repo string
	pflag.StringVarP(&outputDir, "output", "o", ".", "output directory")
	pflag.BoolVar(&debug, "debug", false, "enable debug logs")
	pflag.StringVar(&repo, "repo", "ghcr.io/pomerium/envoy-custom", "image repo")
	pflag.Parse()

	err := fetch(outputDir, repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func logDebug(format string, args ...any) {
	if debug {
		format = "[debug] " + format
		if !strings.HasSuffix(format, "\n") {
			format += "\n"
		}
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

const (
	indexMediaType       = "application/vnd.oci.image.index.v1+json"
	imageConfigMediaType = "application/vnd.oci.image.config.v1+json"
	zstdLayerType        = "application/vnd.oci.image.layer.v1.tar+zstd"
)

const preferredHashAlg = "xxh3"

func newHash() hash.Hash {
	return xxh3.New()
}

type fetchRequest struct {
	manifestDesc v1.Descriptor
	platform     v1.Platform
	version      string
}

type fetchResult struct {
	didUpdate bool
	err       error
}

func fetch(outputDir string, remoteRepoName string) error {
	version := envoyversion.Version()
	ctx := context.Background()
	logDebug("envoy version: %s", version)
	absOutputDir, _ := filepath.Abs(outputDir)
	logDebug("remote repo: %s; output dir: %s", remoteRepoName, absOutputDir)

	repo, err := remote.NewRepository(remoteRepoName)
	if err != nil {
		return err
	}

	logDebug("[remote] fetching index")
	indexDesc, reader, err := repo.FetchReference(ctx, version)
	if err != nil {
		return err
	}
	indexReader := content.NewVerifyReader(reader, indexDesc)
	var index v1.Index
	if err := json.NewDecoder(indexReader).Decode(&index); err != nil {
		return err
	}
	if err := indexReader.Verify(); err != nil {
		return fmt.Errorf("content verification failed for index %s: %w", indexDesc.Digest, err)
	}
	if index.MediaType != indexMediaType {
		return fmt.Errorf("expected reference to be an oci index, got %s instead", index.MediaType)
	}
	if len(index.Manifests) == 0 {
		return fmt.Errorf("remote index is empty")
	}

	logDebug("[remote] found valid index containing %d platforms", len(index.Manifests))

	var wg sync.WaitGroup
	requests := make([]fetchRequest, len(index.Manifests))
	results := make([]fetchResult, len(index.Manifests))
	for i, manifestDesc := range index.Manifests {
		platform := manifestDesc.Platform
		if platform == nil {
			fmt.Fprintf(os.Stderr, "skipping manifest with missing platform info: %s\n", manifestDesc.Digest)
			continue
		}
		logDebug("[remote] found manifest for platform %s/%s", platform.OS, platform.Architecture)

		requests[i] = fetchRequest{
			manifestDesc: manifestDesc,
			platform:     *platform,
			version:      version,
		}
	}

	for i, req := range requests {
		wg.Go(func() {
			didUpdate, err := fetchPlatform(ctx, req, outputDir, repo)
			results[i] = fetchResult{didUpdate, err}
		})
	}
	wg.Wait()
	for i := range len(index.Manifests) {
		req := requests[i]
		res := results[i]
		if res.err != nil {
			fmt.Fprintf(os.Stderr, "%s/%s: error: %s\n", req.platform.OS, req.platform.Architecture, res.err)
			continue
		}
		filename := platformFilename(requests[i].platform)
		if res.didUpdate {
			fmt.Fprintf(os.Stderr, "%s => %s\n", filename, version)
		} else {
			fmt.Fprintf(os.Stderr, "%s (up to date)\n", filename)
		}
	}
	return nil
}

func fetchPlatform(ctx context.Context, req fetchRequest, outputDir string, repo *remote.Repository) (bool, error) {
	dst := filepath.Join(outputDir, platformFilename(req.platform))

	// Check if the file is up to date
	if ok, err := needsUpdate(dst, req.manifestDesc); err != nil {
		return false, err
	} else if !ok {
		return false, nil
	}

	logDebug("[%s] fetching platform manifest", req.platform)
	reader, err := repo.Fetch(ctx, req.manifestDesc)
	if err != nil {
		return false, fmt.Errorf("failed to fetch manifest %s: %w", req.manifestDesc.Digest, err)
	}

	manifestReader := content.NewVerifyReader(reader, req.manifestDesc)
	var manifest v1.Manifest
	if err := json.NewDecoder(manifestReader).Decode(&manifest); err != nil {
		return false, err
	}
	if err := manifestReader.Verify(); err != nil {
		return false, fmt.Errorf("content verification failed for manifest %s: %w", req.manifestDesc.Digest, err)
	}

	var labels map[string]string
	if manifest.Config.MediaType == imageConfigMediaType {
		reader, err := repo.Fetch(ctx, manifest.Config)
		if err != nil {
			return false, fmt.Errorf("failed to fetch image config: %w", err)
		}
		imageReader := content.NewVerifyReader(reader, manifest.Config)
		var ic v1.Image
		if err := json.NewDecoder(imageReader).Decode(&ic); err != nil {
			return false, err
		}
		if err := imageReader.Verify(); err != nil {
			return false, fmt.Errorf("content verification failed for image spec %s: %w", manifest.Config.Digest, err)
		}
		labels = ic.Config.Labels
	}

	if len(manifest.Layers) != 1 {
		return false, fmt.Errorf("expected 1 layer, got %d", len(manifest.Layers))
	}
	layer0 := manifest.Layers[0]

	if layer0.MediaType != zstdLayerType {
		return false, fmt.Errorf("unexpected layer type (want %s, got %s)", zstdLayerType, layer0.MediaType)
	}

	layer, err := repo.Blobs().Fetch(ctx, layer0)
	if err != nil {
		return false, err
	}
	layerReader := content.NewVerifyReader(layer, layer0)
	size, digest, err := extract(dst, layerReader)
	if err != nil {
		return false, fmt.Errorf("failed to extract layer into %s: %w", layer0.Digest, err)
	}
	if err := layerReader.Verify(); err != nil {
		return false, fmt.Errorf("content verification failed for layer %s: %w", layer0.Digest, err)
	}

	lockfile := envoyversion.Lockfile{
		Filename:           dst,
		Digest:             digest,
		Size:               size,
		Version:            req.version,
		ManifestDescriptor: req.manifestDesc,
		Labels:             labels,
	}
	lockfileName := dst + ".lock"
	jsonData, err := json.MarshalIndent(lockfile, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(lockfileName+".tmp", jsonData, 0o444); err != nil {
		return false, fmt.Errorf("failed to write lockfile: %w", err)
	}
	if err := os.Rename(lockfileName+".tmp", lockfileName); err != nil {
		return false, fmt.Errorf("failed to write lockfile: %w", err)
	}
	return true, nil
}

func needsUpdate(dst string, manifestDesc v1.Descriptor) (bool, error) {
	var lockfile envoyversion.Lockfile
	dbgPrefix := fmt.Sprintf("[%s/%s] ", manifestDesc.Platform.OS, manifestDesc.Platform.Architecture)

	fileInfo, err := os.Stat(dst)
	if err != nil {
		if os.IsNotExist(err) {
			logDebug(dbgPrefix + "no binary present; update required")
			return true, nil
		}
		return false, err
	}

	logDebug(dbgPrefix+"reading lockfile %s.lock", dst)
	if data, err := os.ReadFile(dst + ".lock"); err != nil {
		if os.IsNotExist(err) {
			// Clean up artifacts from older versions of this tool
			if _, err := os.Stat(dst + ".sha256"); err == nil {
				_ = os.Remove(dst + ".sha256")
			}
			if _, err := os.Stat(dst + ".version"); err == nil {
				_ = os.Remove(dst + ".version")
			}
			logDebug(dbgPrefix + "no lockfile found; update required")
			return true, nil
		}
		return false, fmt.Errorf("failed to read lockfile for %s: %w", dst, err)
	} else if err := json.Unmarshal(data, &lockfile); err != nil {
		return false, fmt.Errorf("failed to read lockfile for %s: %w", dst, err)
	}

	// Check if the remote manifest matches the local one
	if !content.Equal(lockfile.ManifestDescriptor, manifestDesc) {
		logDebug(dbgPrefix + "local manifest is out of date; update required")
		return true, nil
	}
	logDebug(dbgPrefix + "local manifest is up to date")

	// Check if the file on disk matches the digest in the lockfile
	if fileInfo.Size() != lockfile.Size {
		logDebug(dbgPrefix + "cached binary size does not match the size indicated in the lockfile")
		return true, nil
	}
	logDebug(dbgPrefix + "checking if cached binary checksum matches lockfile")

	hash := newHash()
	file, err := os.Open(dst)
	if err != nil {
		return false, err
	}
	_, err = io.Copy(hash, file)
	_ = file.Close()
	if err != nil {
		return false, err
	}
	if fmt.Sprintf("%s:%x", preferredHashAlg, hash.Sum(nil)) != lockfile.Digest {
		logDebug(dbgPrefix + "cached binary checksum mismatch, update required")
		return true, nil
	}

	logDebug(dbgPrefix + "cached binary is up to date")
	return false, nil
}

func extract(outputFilename string, layer io.Reader) (_ int64, _ string, retErr error) {
	logDebug("extracting binary to %s", outputFilename)

	tmpFilename := outputFilename + ".tmp"
	file, err := os.Create(tmpFilename)
	if err != nil {
		return 0, "", err
	}
	defer func() {
		if retErr != nil {
			_ = file.Close()
		}
		if _, err := os.Stat(tmpFilename); err == nil {
			_ = os.Remove(tmpFilename)
		}
	}()
	decompressor, err := zstd.NewReader(layer, zstd.WithDecoderConcurrency(runtime.NumCPU()))
	if err != nil {
		return 0, "", err
	}
	defer decompressor.Close()
	tarReader := tar.NewReader(decompressor)

	hdr, err := tarReader.Next()
	if err != nil {
		return 0, "", err
	}
	if hdr.Name != "envoy" && hdr.Name != "envoy.stripped" {
		return 0, "", fmt.Errorf("encountered unknown file in archive: %s", hdr.Name)
	}

	hash := newHash()
	tr := io.TeeReader(tarReader, hash)
	size, err := io.Copy(file, tr)
	if err != nil {
		return 0, "", err
	}
	if _, err := tarReader.Next(); !errors.Is(err, io.EOF) {
		return 0, "", fmt.Errorf("expected archive to contain only 1 file, but found more")
	}

	digest := fmt.Sprintf("%s:%x", preferredHashAlg, hash.Sum(nil))
	if err := file.Close(); err != nil {
		return 0, "", err
	}
	if err := os.Rename(tmpFilename, outputFilename); err != nil {
		return 0, "", err
	}

	logDebug("extracted binary to %s (size: %d; digest: %s)", outputFilename, size, digest)
	return size, digest, nil
}

var archMappings = map[string]string{
	"x86_64":  "amd64",
	"aarch64": "arm64",
}

func platformFilename(platform v1.Platform) string {
	arch := platform.Architecture
	if m, ok := archMappings[platform.Architecture]; ok {
		arch = m
	}
	return fmt.Sprintf("envoy-%s-%s", platform.OS, arch)
}
