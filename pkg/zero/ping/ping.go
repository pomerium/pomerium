package clusterping

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/go-jose/go-jose/v3"

	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/endpoints"
)

type CheckErrorCode int

const (
	ErrInvalidCert CheckErrorCode = iota
	ErrDNSError
	ErrConnectionError
	ErrKeyNotFound
	ErrUnexpectedResponse
)

type CheckError struct {
	Code CheckErrorCode
	Err  error
}

func NewCheckError(code CheckErrorCode, err error) *CheckError {
	return &CheckError{
		Code: code,
		Err:  err,
	}
}

var errorCodeToString = map[CheckErrorCode]string{
	ErrInvalidCert:        "invalid certificate",
	ErrDNSError:           "DNS error",
	ErrConnectionError:    "connection error",
	ErrKeyNotFound:        "key not found",
	ErrUnexpectedResponse: "unexpected response",
}

func (e *CheckError) Error() string {
	return fmt.Sprintf("%s: %v", errorCodeToString[e.Code], e.Err)
}

func (e *CheckError) Unwrap() error {
	return e.Err
}

func GetJWKSURL(host string) string {
	return (&url.URL{
		Scheme: "https",
		Host:   host,
		Path:   endpoints.PathJWKS,
	}).String()
}

func CheckKey(
	ctx context.Context,
	jwksURL string,
	key jose.JSONWebKey,
	client *http.Client,
) error {
	keys, err := fetchKeys(ctx, client, jwksURL)
	if err != nil {
		return err
	}

	if !containsKey(keys, key) {
		return NewCheckError(ErrKeyNotFound, fmt.Errorf("key %s not found in JWKS", key.KeyID))
	}

	return nil
}

func containsKey(keys []jose.JSONWebKey, key jose.JSONWebKey) bool {
	for _, k := range keys {
		if k.KeyID == key.KeyID {
			return true
		}
	}
	return false
}

func fetchKeys(ctx context.Context, client *http.Client, jwksURL string) ([]jose.JSONWebKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return nil, convertRequestError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, NewCheckError(ErrUnexpectedResponse, fmt.Errorf("unexpected status code %d", resp.StatusCode))
	}

	if resp.Header.Get("Content-Type") != "application/json" {
		return nil, NewCheckError(ErrUnexpectedResponse, fmt.Errorf("unexpected content type %s", resp.Header.Get("Content-Type")))
	}

	var jwks struct {
		Keys []jose.JSONWebKey `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, NewCheckError(ErrUnexpectedResponse, fmt.Errorf("error decoding response: %w", err))
	}

	return jwks.Keys, nil
}

func convertRequestError(err error) error {
	if tlsErr := new(tls.CertificateVerificationError); errors.As(err, &tlsErr) {
		return NewCheckError(ErrInvalidCert, err)
	}
	if dnsErr := new(net.DNSError); errors.As(err, &dnsErr) {
		return NewCheckError(ErrDNSError, err)
	}
	if netErr := new(net.Error); errors.As(err, netErr) {
		return NewCheckError(ErrConnectionError, err)
	}

	return fmt.Errorf("error making request: %w", err)
}
