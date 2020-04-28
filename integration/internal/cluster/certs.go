package cluster

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

type TLSCerts struct {
	CA   string
	Cert string
	Key  string
}

func bootstrapCerts(ctx context.Context) (*TLSCerts, error) {
	err := run(ctx, "mkcert", withArgs("-install"))
	if err != nil {
		return nil, fmt.Errorf("error install root certificate: %w", err)
	}

	var buf bytes.Buffer
	err = run(ctx, "mkcert", withArgs("-CAROOT"), withStdout(&buf))
	if err != nil {
		return nil, fmt.Errorf("error running mkcert")
	}

	caPath := strings.TrimSpace(buf.String())
	ca, err := ioutil.ReadFile(filepath.Join(caPath, "rootCA.pem"))
	if err != nil {
		return nil, fmt.Errorf("error reading root ca: %w", err)
	}

	wd := filepath.Join(os.TempDir(), uuid.New().String())
	err = os.MkdirAll(wd, 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating temporary directory: %w", err)
	}

	err = run(ctx, "mkcert", withArgs("*.localhost.pomerium.io"), withWorkingDir(wd))
	if err != nil {
		return nil, fmt.Errorf("error generating certificates: %w", err)
	}

	cert, err := ioutil.ReadFile(filepath.Join(wd, "_wildcard.localhost.pomerium.io.pem"))
	if err != nil {
		return nil, fmt.Errorf("error reading certificate: %w", err)
	}

	key, err := ioutil.ReadFile(filepath.Join(wd, "_wildcard.localhost.pomerium.io-key.pem"))
	if err != nil {
		return nil, fmt.Errorf("error reading certificate key: %w", err)
	}

	return &TLSCerts{
		CA:   string(ca),
		Cert: string(cert),
		Key:  string(key),
	}, nil
}
