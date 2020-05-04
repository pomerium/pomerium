package envoy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/natefinch/atomic"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/rs/zerolog"
)

const (
	workingDirectoryName = ".pomerium-envoy"
	configFileName       = "envoy-config.yaml"
)

// A Server is a pomerium proxy implemented via envoy.
type Server struct {
	wd  string
	cmd *exec.Cmd

	grpcPort, httpPort string
}

// NewServer creates a new server with traffic routed by envoy.
func NewServer(grpcPort, httpPort string) (*Server, error) {
	wd := filepath.Join(os.TempDir(), workingDirectoryName)
	err := os.MkdirAll(wd, 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating temporary working directory for envoy: %w", err)
	}

	srv := &Server{
		wd:       wd,
		grpcPort: grpcPort,
		httpPort: httpPort,
	}

	err = srv.writeConfig()
	if err != nil {
		return nil, fmt.Errorf("error writing initial envoy configuration: %w", err)
	}

	return srv, nil
}

func (srv *Server) Run(ctx context.Context) error {
	srv.cmd = exec.CommandContext(ctx, "envoy",
		"-c", configFileName,
		"--log-level", log.Logger.GetLevel().String(),
		"--log-format", "%l--%n--%v",
		"--log-format-escaped",
	)
	srv.cmd.Dir = srv.wd

	stderr, err := srv.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("error creating stderr pipe for envoy: %w", err)
	}
	go srv.handleLogs(stderr)

	stdout, err := srv.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error creating stderr pipe for envoy: %w", err)
	}
	go srv.handleLogs(stdout)

	// make sure envoy is killed if we're killed
	srv.cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}
	return srv.cmd.Run()
}

func (srv *Server) writeConfig() error {
	return atomic.WriteFile(filepath.Join(srv.wd, configFileName), strings.NewReader(`
node:
  id: pomerium-envoy
  cluster: pomerium-envoy

admin:
  access_log_path: /tmp/admin_access.log
  address:
    socket_address: { address: 127.0.0.1, port_value: 9901 }

dynamic_resources:
  cds_config:
    ads: {}
    resource_api_version: V3
  lds_config:
    ads: {}
    resource_api_version: V3
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc:
          cluster_name: pomerium-control-plane-grpc
static_resources:
  clusters:
  - name: pomerium-control-plane-grpc
    connect_timeout: { seconds: 5 }
    type: STATIC
    hosts:
    - socket_address:
        address: 127.0.0.1
        port_value: `+srv.grpcPort+`
    http2_protocol_options: {}
`))
}

func (srv *Server) handleLogs(stdout io.ReadCloser) {
	fileNameAndNumberRE := regexp.MustCompile(`^(\[[^:]+:[0-9]+\])\s(.*)$`)

	s := bufio.NewScanner(stdout)
	for s.Scan() {
		ln := s.Text()

		// format: level--name--message
		// message is c-escaped

		lvl := zerolog.TraceLevel
		if pos := strings.Index(ln, "--"); pos >= 0 {
			lvlstr := ln[:pos]
			ln = ln[pos+2:]
			if x, err := zerolog.ParseLevel(lvlstr); err == nil {
				lvl = x
			}
		}

		name := ""
		if pos := strings.Index(ln, "--"); pos >= 0 {
			name = ln[:pos]
			ln = ln[pos+2:]
		}

		msg := fileNameAndNumberRE.ReplaceAllString(ln, "\"$2\"")
		if s, err := strconv.Unquote(msg); err == nil {
			msg = s
		}

		log.WithLevel(lvl).Str("service", "envoy").Str("name", name).Msg(msg)
	}
}
