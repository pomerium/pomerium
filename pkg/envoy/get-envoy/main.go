package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"slices"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/envoy/envoyversion"
)

var (
	targets = []string{
		"darwin-amd64",
		"darwin-arm64",
		"linux-amd64",
		"linux-arm64",
	}
	baseURL = "https://github.com/pomerium/envoy-custom/releases/download/v" + envoyversion.Version()
)

func main() {
	log.SetLevel(zerolog.InfoLevel)
	ctx := context.Background()
	err := run(ctx, os.Args)
	if err != nil {
		log.Fatal().Err(err).Send()
	}
}

func run(ctx context.Context, args []string) error {
	mode := "all"
	if len(args) > 1 {
		mode = args[1]
	}

	switch mode {
	case "all":
		return runAll(ctx)
	case "current":
		return runCurrent(ctx)
	default:
		if slices.Contains(targets, mode) {
			return runArch(ctx, mode)
		}
	}

	return fmt.Errorf("unknown mode: %s", mode)
}

func runAll(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	for _, target := range targets {

		eg.Go(func() error {
			return download(ctx, "./envoy-"+target, baseURL+"/envoy-"+target)
		})
		eg.Go(func() error {
			return download(ctx, "./envoy-"+target+".sha256", baseURL+"/envoy-"+target+".sha256")
		})
		eg.Go(func() error {
			return os.WriteFile("./envoy-"+target+".version", []byte(envoyversion.Version()+"\n"), 0o600)
		})
	}
	return eg.Wait()
}

func runCurrent(ctx context.Context) error {
	return runArch(ctx, runtime.GOOS+"-"+runtime.GOARCH)
}

func runArch(ctx context.Context, arch string) error {
	err := download(ctx, "./envoy", baseURL+"/envoy-"+arch)
	if err != nil {
		return err
	}

	err = os.Chmod("./envoy", 0o755)
	if err != nil {
		return err
	}

	return nil
}

func download(
	ctx context.Context,
	dstPath string,
	srcURL string,
) error {
	fi, err := os.Stat(dstPath)
	if err == nil {
		lastModified, err := getURLLastModified(ctx, srcURL)
		if err != nil {
			return fmt.Errorf("error getting download last modified (url=%s): %w", srcURL, err)
		}

		if timesMatch(fi.ModTime(), lastModified) {
			log.Ctx(ctx).Debug().Str("url", srcURL).Str("dst", dstPath).Msg("skipping download")
			return nil
		}

	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error reading destination path file info (dst=%s): %w", dstPath, err)
	}

	log.Ctx(ctx).Info().Str("url", srcURL).Str("dst", dstPath).Msg("downloading")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srcURL, nil)
	if err != nil {
		return fmt.Errorf("error creating GET request for download (url=%s): %w", srcURL, err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error making GET request for download (url=%s): %w", srcURL, err)
	}
	defer res.Body.Close()

	if err := checkHTTPStatus(srcURL, res); err != nil {
		return err
	}

	dst, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("error creating downloaded file (url=%s dst=%s): %w", srcURL, dstPath, err)
	}

	_, err = io.Copy(dst, res.Body)
	if err != nil {
		_ = dst.Close()
		_ = os.Remove(dstPath)
		return fmt.Errorf("error copying downloaded file (url=%s dst=%s): %w", srcURL, dstPath, err)
	}

	err = dst.Close()
	if err != nil {
		_ = os.Remove(dstPath)
		return fmt.Errorf("error closing destination file: %w", err)
	}

	if lastModified, err := time.Parse(http.TimeFormat, res.Header.Get("Last-Modified")); err == nil {
		err = os.Chtimes(dstPath, time.Time{}, lastModified)
		if err != nil {
			return fmt.Errorf("error writing last modified timestamp: %w", err)
		}
	}

	return nil
}

func getURLLastModified(
	ctx context.Context,
	srcURL string,
) (time.Time, error) {
	// check to see if the file needs to be updated
	headReq, err := http.NewRequestWithContext(ctx, http.MethodHead, srcURL, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("error creating head request for download: %w", err)
	}

	res, err := http.DefaultClient.Do(headReq)
	if err != nil {
		return time.Time{}, fmt.Errorf("error making head request for download: %w", err)
	}
	defer res.Body.Close()

	if err := checkHTTPStatus(srcURL, res); err != nil {
		return time.Time{}, err
	}

	return time.Parse(http.TimeFormat, res.Header.Get("Last-Modified"))
}

func checkHTTPStatus(srcURL string, res *http.Response) error {
	if res.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
		return fmt.Errorf("unexpected status code for download (url=%s): %s %s", srcURL, res.Status, msg)
	}
	return nil
}

func timesMatch(tm1, tm2 time.Time) bool {
	diff := tm2.Sub(tm1)
	return diff >= -5*time.Minute && diff <= 5*time.Minute
}
