package evaluator

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	lru "github.com/hashicorp/golang-lru"
	"github.com/rakyll/statik/fs"

	_ "github.com/pomerium/pomerium/authorize/evaluator/opa/policy" // load static assets
)

var isValidClientCertificateCache, _ = lru.New2Q(100)

func isValidClientCertificate(ca, cert string) (bool, error) {
	// when ca is the empty string, client certificates are always accepted
	if ca == "" {
		return true, nil
	}

	// when cert is the empty string, no client certificate was supplied
	if cert == "" {
		return false, nil
	}

	cacheKey := [2]string{ca, cert}

	value, ok := isValidClientCertificateCache.Get(cacheKey)
	if ok {
		return value.(bool), nil
	}

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(ca))

	xcert, err := parseCertificate(cert)
	if err != nil {
		return false, err
	}

	_, verifyErr := xcert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	valid := verifyErr == nil

	isValidClientCertificateCache.Add(cacheKey, valid)

	return valid, nil
}

func parseCertificate(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("invalid certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unknown PEM type: %s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

const statikNamespace = "rego"

func readPolicy(fn string) ([]byte, error) {
	statikFS, err := fs.NewWithNamespace(statikNamespace)
	if err != nil {
		return nil, err
	}
	r, err := statikFS.Open(fn)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return ioutil.ReadAll(r)
}
