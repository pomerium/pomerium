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

// WithTestRedisCluster creates a new redis cluster 3 node cluster.
func WithTestRedisCluster(handler func(rawURL string) error) error {
	ctx, clearTimeout := context.WithTimeout(context.Background(), maxWait)
	defer clearTimeout()

	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		return err
	}

	redises := make([]*dockertest.Resource, 3)
	for i := range redises {
		conf := "cluster-enabled yes\ncluster-config-file nodes.conf"
		r, err := pool.RunWithOptions(&dockertest.RunOptions{
			Hostname:   fmt.Sprintf("redis%d", i),
			Repository: "redis",
			Tag:        "6",
			Entrypoint: []string{
				"/bin/bash", "-c",
				`echo "` + conf + `" >/tmp/redis.conf && chmod 0777 /tmp/redis.conf && exec docker-entrypoint.sh /tmp/redis.conf`,
			},
			ExposedPorts: []string{
				"6379/tcp",
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

		redises[i] = r
	}
	addrs := make([]string, 3)
	for i, r := range redises {
		addrs[i] = net.JoinHostPort(
			r.Container.NetworkSettings.IPAddress,
			"6379",
		)
	}

	for _, addr := range addrs {
		err := pool.Retry(func() error {
			options, err := redis.ParseURL(fmt.Sprintf("redis://%s/0", addr))
			if err != nil {
				return err
			}

			client := redis.NewClient(options)
			defer client.Close()

			return client.Ping(ctx).Err()
		})
		if err != nil {
			return err
		}
	}

	// join the nodes to the cluster
	err = bootstrapRedisCluster(ctx, redises)
	if err != nil {
		return err
	}

	e := handler(fmt.Sprintf("redis+cluster://%s", strings.Join(addrs, ",")))

	for _, r := range redises {
		if err := pool.Purge(r); err != nil {
			return err
		}
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
			Hostname:   fmt.Sprintf("redis%d", i),
			Repository: "redis",
			Tag:        "6",
			ExposedPorts: []string{
				"6379/tcp",
				"26379/tcp",
			},
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
		conf := fmt.Sprintf("sentinel monitor master %s 6379 %d\n",
			redises[0].Container.NetworkSettings.IPAddress, len(redises))
		if i > 0 {
			conf += fmt.Sprintf("sentinel known-slave master %s 6379\n",
				redises[i].Container.NetworkSettings.IPAddress)
		}

		r, err := pool.RunWithOptions(&dockertest.RunOptions{
			Hostname:   fmt.Sprintf("sentineld%d", i),
			Repository: "redis",
			Tag:        "6",
			Entrypoint: []string{
				"/bin/bash", "-c",
				`echo "` + conf + `" >/tmp/sentinel.conf && chmod 0777 /tmp/sentinel.conf && exec docker-entrypoint.sh /tmp/sentinel.conf --sentinel`,
			},
			ExposedPorts: []string{
				"6379/tcp",
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
		addrs[i] = net.JoinHostPort(
			r.Container.NetworkSettings.IPAddress,
			"26379",
		)
	}

	redisURL := fmt.Sprintf("redis+sentinel://%s/master/0", strings.Join(addrs, ","))

	for _, r := range redises {
		addr := net.JoinHostPort(
			r.Container.NetworkSettings.IPAddress,
			"6379",
		)
		if err := pool.Retry(func() error {
			options, err := redis.ParseURL(fmt.Sprintf("redis://%s/0", addr))
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

func bootstrapRedisCluster(ctx context.Context, resources []*dockertest.Resource) error {
	clients := make([]redis.UniversalClient, len(resources))
	for i, r := range resources {
		addr := net.JoinHostPort(r.Container.NetworkSettings.IPAddress, "6379")
		options, err := redis.ParseURL(fmt.Sprintf("redis://%s/0", addr))
		if err != nil {
			return err
		}
		clients[i] = redis.NewClient(options)
		defer func() { _ = clients[i].Close() }()

		if i > 0 {
			err := clients[i].ClusterMeet(ctx, resources[0].Container.NetworkSettings.IPAddress, "6379").Err()
			if err != nil {
				return err
			}
		}
	}

	// set slots
	const redisSlotCount = 16384
	assignments := make([][]int, len(resources))
	for i := 0; i < redisSlotCount; i++ {
		assignments[i%len(assignments)] = append(assignments[i%len(assignments)], i)
	}
	for i, c := range clients {
		err := c.ClusterAddSlots(ctx, assignments[i]...).Err()
		if err != nil {
			return err
		}
	}

	// wait for ready
	ticker := time.NewTicker(time.Millisecond * 50)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		ready := 0
		for _, c := range clients {
			str, err := c.ClusterInfo(ctx).Result()
			if err != nil {
				return err
			}
			if strings.Contains(str, "cluster_state:ok") {
				ready++
			}
		}
		if ready == len(clients) {
			return nil
		}
	}
}
