package golangcilint

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
)

const (
	linterBin = "golangci-lint"
	toolFile  = ".tool-versions"
)

type Options struct {
	basePath string
	w        io.Writer
}

func (o *Options) Apply(opts ...Option) {
	for _, opt := range opts {
		opt(o)
	}
}

type Option func(*Options)

func WithBasePath(path string) Option {
	return func(o *Options) {
		o.basePath = path
	}
}

func WithOutput(w io.Writer) Option {
	return func(o *Options) {
		o.w = w
	}
}

type installer struct {
	ctx context.Context
	*Options
}

func defaultOptions() *Options {
	return &Options{
		basePath: "./",
		w:        os.Stdout,
	}
}

func InstallLinter(ctx context.Context, opts ...Option) error {
	inst := installer{
		ctx:     ctx,
		Options: defaultOptions(),
	}
	inst.Options.Apply(opts...)
	w := inst.w
	expectedVersion, err := inst.expectedVersion()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Expected version : %s\n", expectedVersion)
	ok, err := inst.hasBinary()
	if err != nil {
		return err
	}
	gotVersion := ""
	if ok {
		v, err := inst.installedVersion()
		if err != nil {
			return err
		}
		gotVersion = v
	}
	fmt.Fprintf(w, "Got version : %s\n", gotVersion)
	shouldDownload := !ok || (expectedVersion != gotVersion)
	if shouldDownload {
		fmt.Fprintf(w, "mismatched versions, downloading...")
		if err := inst.runInstaller(expectedVersion); err != nil {
			return err
		}
		v, err := inst.installedVersion()
		if err != nil {
			return fmt.Errorf("failed to verify installed version")
		}
		fmt.Fprintf(w, "Installed version : %s\n", v)

	} else {
		fmt.Fprintf(w, "tool up-to-date\n")
	}
	return nil
}

func (i *installer) hasBinary() (bool, error) {
	_, err := os.Stat(
		path.Join(i.basePath, fmt.Sprintf("bin/%s", linterBin)),
	)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (i *installer) expectedVersion() (version string, err error) {
	toolFile := path.Join(i.basePath, toolFile)
	if _, err := os.Stat(toolFile); err != nil {
		return "", err
	}
	data, err := os.ReadFile(toolFile)
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, linterBin) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strings.TrimSpace(fields[1]), nil
			}
		}
	}
	return "", fmt.Errorf("no expected version found")
}

func (i *installer) runInstaller(version string) error {
	const url = "https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh"

	req, err := http.NewRequestWithContext(i.ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "pomerium-installer")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("failed to download installer: status %s", resp.Status)
	}
	v := "v" + version
	cmd := exec.CommandContext(i.ctx, "sh", "-s", v)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer stdin.Close()
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	var wg sync.WaitGroup

	wg.Go(func() {
		_, _ = io.Copy(stdin, resp.Body)
		_ = stdin.Close()
	})

	wg.Go(func() {
		sc := bufio.NewScanner(stdoutPipe)
		for sc.Scan() {
			fmt.Fprintln(i.w, sc.Text())
		}
	})

	wg.Go(func() {
		sc := bufio.NewScanner(stderrPipe)
		for sc.Scan() {
			fmt.Fprintln(i.w, sc.Text())
		}
	})
	wg.Wait()
	if err := cmd.Wait(); err != nil {
		return err
	}
	return nil
}

func (i *installer) installedVersion() (gotVersion string, err error) {
	p := path.Clean(path.Join(i.basePath, "bin/golangci-lint"))
	cmd := exec.Command(p, "--version")
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		sc := bufio.NewScanner(stdoutPipe)
		for sc.Scan() {
			line := sc.Text()
			if strings.Contains(line, "has version") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					gotVersion = strings.TrimSpace(fields[3])
					break
				}
			}
		}
	})

	if err := cmd.Wait(); err != nil {
		return "", err
	}
	wg.Wait()
	return gotVersion, err
}
