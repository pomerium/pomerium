package cluster

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// TLSCerts holds the certificate authority, certificate and certificate key for a TLS connection.
type TLSCerts struct {
	CA     []byte
	Cert   []byte
	Key    []byte
	Client struct {
		Cert []byte
		Key  []byte
	}
}

// TLSCertsBundle holds various TLSCerts.
type TLSCertsBundle struct {
	Trusted      TLSCerts
	WronglyNamed TLSCerts
	Untrusted    TLSCerts
}

func bootstrapCerts(ctx context.Context) (*TLSCertsBundle, error) {
	wd := filepath.Join(os.TempDir(), "pomerium-integration-tests", "certs")
	err := os.MkdirAll(wd, 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating integration tests working directory: %w", err)
	}

	var bundle TLSCertsBundle

	var generators = []struct {
		certs   *TLSCerts
		caroot  string
		install bool
		name    string
	}{
		{&bundle.Trusted, filepath.Join(wd, "trusted"), true, "*.localhost.pomerium.io"},
		{&bundle.WronglyNamed, filepath.Join(wd, "trusted"), true, "*.localhost.notpomerium.io"},
		{&bundle.Untrusted, filepath.Join(wd, "untrusted"), false, "*.localhost.pomerium.io"},
	}

	for _, generator := range generators {
		err = os.MkdirAll(generator.caroot, 0755)
		if err != nil {
			return nil, fmt.Errorf("error creating integration tests %s working directory: %w",
				filepath.Base(generator.caroot), err)
		}

		args := []string{"-install"}
		env := []string{"CAROOT=" + generator.caroot}
		if !generator.install {
			env = append(env, "TRUST_STORES=xxx")
		}
		err = run(ctx, "mkcert", withArgs(args...), withEnv(env...))
		if err != nil {
			return nil, fmt.Errorf("error creating %s certificate authority: %w",
				filepath.Base(generator.caroot), err)
		}

		fp := filepath.Join(generator.caroot, "rootCA.pem")
		generator.certs.CA, err = ioutil.ReadFile(fp)
		if err != nil {
			return nil, fmt.Errorf("error reading %s root ca: %w",
				filepath.Base(generator.caroot), err)
		}

		root := filepath.Join(generator.caroot, strings.ReplaceAll(generator.name, "*", "_wildcard"))
		fileMap := map[string]*[]byte{
			root + ".pem":            &generator.certs.Cert,
			root + "-client.pem":     &generator.certs.Client.Cert,
			root + "-key.pem":        &generator.certs.Key,
			root + "-client-key.pem": &generator.certs.Client.Key,
		}

		regenerate := false
		for name := range fileMap {
			if _, err := os.Stat(name); err != nil {
				regenerate = true
			}
		}

		if regenerate {
			env = []string{"CAROOT=" + generator.caroot}
			err = run(ctx, "mkcert",
				withArgs(generator.name),
				withWorkingDir(generator.caroot),
				withEnv(env...))
			if err != nil {
				return nil, fmt.Errorf("error generating %s certificates: %w",
					filepath.Base(generator.caroot), err)
			}
			err = run(ctx, "mkcert",
				withArgs("-client", generator.name),
				withWorkingDir(generator.caroot),
				withEnv(env...))
			if err != nil {
				return nil, fmt.Errorf("error generating %s client certificates: %w",
					filepath.Base(generator.caroot), err)
			}
		}

		for name, ptr := range fileMap {
			*ptr, err = ioutil.ReadFile(name)
			if err != nil {
				return nil, fmt.Errorf("error reading %s: %w",
					name, err)
			}
		}
	}

	return &bundle, nil
}
