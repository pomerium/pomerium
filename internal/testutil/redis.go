package testutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/ory/dockertest/v3"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

const maxWait = time.Minute

// WithTestRedis creates a test a test redis instance using docker.
func WithTestRedis(useTLS bool, handler func(rawURL string) error) error {
	ctx, clearTimeout := context.WithTimeout(context.Background(), maxWait)
	defer clearTimeout()

	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		return err
	}

	opts := &dockertest.RunOptions{
		Repository: "redis",
		Tag:        "6",
	}
	scheme := "redis"
	if useTLS {
		opts.Mounts = []string{
			filepath.Join(TestDataRoot(), "tls") + ":/tls",
		}
		opts.Cmd = []string{
			"--port", "0",
			"--tls-port", "6379",
			"--tls-cert-file", "/tls/redis.crt",
			"--tls-key-file", "/tls/redis.key",
			"--tls-ca-cert-file", "/tls/ca.crt",
		}
		scheme = "rediss"
	}

	resource, err := pool.RunWithOptions(opts)
	if err != nil {
		return err
	}
	_ = resource.Expire(uint(maxWait.Seconds()))

	redisURL := fmt.Sprintf("%s://%s/0", scheme, resource.GetHostPort("6379/tcp"))
	if err := pool.Retry(func() error {
		options, err := redis.ParseURL(redisURL)
		if err != nil {
			return err
		}
		if useTLS {
			options.TLSConfig = RedisTLSConfig()
		}

		client := redis.NewClient(options)
		defer client.Close()

		return client.Ping(ctx).Err()
	}); err != nil {
		_ = pool.Purge(resource)
		return err
	}

	e := handler(redisURL)

	if err := pool.Purge(resource); err != nil {
		return err
	}

	return e
}

// RedisTLSConfig returns the TLS Config to use with redis.
func RedisTLSConfig() *tls.Config {
	cert, err := cryptutil.CertificateFromFile(
		filepath.Join(TestDataRoot(), "tls", "redis.crt"),
		filepath.Join(TestDataRoot(), "tls", "redis.key"),
	)
	if err != nil {
		panic(err)
	}
	caCertPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile(filepath.Join(TestDataRoot(), "tls", "ca.crt"))
	if err != nil {
		panic(err)
	}
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}
	return tlsConfig
}
