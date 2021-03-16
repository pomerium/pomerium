package testutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"

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

// WithTestRedisSentinel creates a new redis sentinel 3 node cluster.
func WithTestRedisSentinel(handler func(rawURL string) error) error {
	ctx, clearTimeout := context.WithTimeout(context.Background(), maxWait)
	defer clearTimeout()

	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		return err
	}

	redises := make([]*dockertest.Resource, 3)
	for i := range redises {
		r, err := pool.RunWithOptions(&dockertest.RunOptions{
			Repository: "redis",
			Tag:        "6",
		})
		if err != nil {
			return err
		}
		defer r.Close()
		_ = r.Expire(uint(maxWait.Seconds()))

		redises[i] = r
	}

	sentinels := make([]*dockertest.Resource, len(redises))
	for i := range sentinels {
		h1, p1, err := net.SplitHostPort(redises[0].GetHostPort("6379/tcp"))
		if err != nil {
			return err
		}

		conf := fmt.Sprintf("sentinel monitor master %s %s %d\n", h1, p1, len(redises))
		if i > 0 {
			h, p, err := net.SplitHostPort(redises[i].GetHostPort("6379/tcp"))
			if err != nil {
				return err
			}
			conf += fmt.Sprintf("sentinel known-slave master %s %s\n", h, p)
		}

		r, err := pool.RunWithOptions(&dockertest.RunOptions{
			Repository: "redis",
			Tag:        "6",
			Entrypoint: []string{
				"/bin/bash", "-c",
				`echo "` + conf + `" >/tmp/sentinel.conf && chmod 0777 /tmp/sentinel.conf && exec docker-entrypoint.sh /tmp/sentinel.conf --sentinel`,
			},
			ExposedPorts: []string{
				"26379/tcp",
			},
		})
		if err != nil {
			return err
		}
		defer r.Close()
		_ = r.Expire(uint(maxWait.Seconds()))

		go func() {
			_ = pool.Client.Logs(docker.LogsOptions{
				Context:      ctx,
				Stderr:       true,
				Stdout:       true,
				Follow:       true,
				Timestamps:   true,
				Container:    r.Container.ID,
				OutputStream: os.Stderr,
				ErrorStream:  os.Stderr,
			})
		}()
		sentinels[i] = r
	}

	addrs := make([]string, len(sentinels))
	for i, r := range sentinels {
		addrs[i] = r.GetHostPort("26379/tcp")
	}

	redisURL := fmt.Sprintf("redis-sentinel://%s/master/0", strings.Join(addrs, ","))

	for _, r := range redises {
		if err := pool.Retry(func() error {
			options, err := redis.ParseURL(fmt.Sprintf("redis://%s/0", r.GetHostPort("6379/tcp")))
			if err != nil {
				return err
			}

			client := redis.NewClient(options)
			defer client.Close()

			return client.Ping(ctx).Err()
		}); err != nil {
			_ = pool.Purge(r)
			return err
		}
	}
	for _, r := range sentinels {
		if err := pool.Retry(func() error {
			options, err := redis.ParseURL(fmt.Sprintf("redis://%s/0", r.GetHostPort("26379/tcp")))
			if err != nil {
				return err
			}

			client := redis.NewClient(options)
			defer client.Close()

			return client.Ping(ctx).Err()
		}); err != nil {
			_ = pool.Purge(r)
			return err
		}
	}

	e := handler(redisURL)

	for _, r := range append(redises, sentinels...) {
		if err := pool.Purge(r); err != nil {
			return err
		}
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
