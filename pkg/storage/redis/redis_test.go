package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

var db *Backend

func cleanup(ctx context.Context, db *Backend, t *testing.T) {
	require.NoError(t, db.client.FlushAll(ctx).Err())
}

func tlsConfig(rawURL string, t *testing.T) *tls.Config {
	if !strings.HasPrefix(rawURL, "rediss") {
		return nil
	}
	cert, err := cryptutil.CertificateFromFile("./testdata/tls/redis.crt", "./testdata/tls/redis.key")
	require.NoError(t, err)
	caCertPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile("./testdata/tls/ca.crt")
	require.NoError(t, err)
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{*cert},
	}
	return tlsConfig
}

func runWithRedisDockerImage(t *testing.T, runOpts *dockertest.RunOptions, withTLS bool, testFunc func(t *testing.T)) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to docker: %s", err)
	}
	resource, err := pool.RunWithOptions(runOpts)
	if err != nil {
		t.Fatalf("Could not start resource: %s", err)
	}
	resource.Expire(30)

	defer func() {
		if err := pool.Purge(resource); err != nil {
			t.Fatalf("Could not purge resource: %s", err)
		}
	}()

	scheme := "redis"
	if withTLS {
		scheme = "rediss"
	}
	address := fmt.Sprintf(scheme+"://localhost:%s/0", resource.GetPort("6379/tcp"))
	if err := pool.Retry(func() error {
		var err error
		db, err = New(address, WithTLSConfig(tlsConfig(address, t)))
		if err != nil {
			return err
		}
		err = db.client.Ping(context.Background()).Err()
		return err
	}); err != nil {
		t.Fatalf("Could not connect to docker: %s", err)
	}

	testFunc(t)
}

//func TestDB(t *testing.T) {
//	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
//		t.Skip("Github action can not run docker on MacOS")
//	}
//
//	cwd, err := os.Getwd()
//	assert.NoError(t, err)
//
//	tlsCmd := []string{
//		"--port", "0",
//		"--tls-port", "6379",
//		"--tls-cert-file", "/tls/redis.crt",
//		"--tls-key-file", "/tls/redis.key",
//		"--tls-ca-cert-file", "/tls/ca.crt",
//	}
//	tests := []struct {
//		name    string
//		withTLS bool
//		runOpts *dockertest.RunOptions
//	}{
//		{"redis", false, &dockertest.RunOptions{Repository: "redis", Tag: "latest"}},
//		{"redis TLS", true, &dockertest.RunOptions{Repository: "redis", Tag: "latest", Cmd: tlsCmd, Mounts: []string{cwd + "/testdata/tls:/tls"}}},
//	}
//
//	for _, tc := range tests {
//		t.Run(tc.name, func(t *testing.T) {
//			runWithRedisDockerImage(t, tc.runOpts, tc.withTLS, testDB)
//		})
//	}
//}

func TestChangeSignal(t *testing.T) {
	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*10)
	defer clearTimeout()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	require.NoError(t, testutil.WithTestRedis(func(rawURL string) error {
		backend1, err := New(rawURL)
		require.NoError(t, err)
		defer func() { _ = backend1.Close() }()

		backend2, err := New(rawURL)
		require.NoError(t, err)
		defer func() { _ = backend2.Close() }()

		ch := backend1.onChange.Bind()
		defer backend1.onChange.Unbind(ch)

		go func() {
			ticker := time.NewTicker(time.Millisecond * 100)
			defer ticker.Stop()
			for {
				_ = backend2.Put(ctx, &databroker.Record{
					Type: "TYPE",
					Id:   "ID",
				})
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()

		select {
		case <-ch:
		case <-ctx.Done():
			t.Fatal("expected signal to be fired when another backend triggers a change")
		}

		return nil
	}))
}

func TestExpiry(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, testutil.WithTestRedis(func(rawURL string) error {
		backend, err := New(rawURL, WithExpiry(0))
		require.NoError(t, err)
		defer func() { _ = backend.Close() }()

		for i := 0; i < 1000; i++ {
			assert.NoError(t, backend.Put(ctx, &databroker.Record{
				Type: "TYPE",
				Id:   fmt.Sprint(i),
			}))
		}
		stream, err := backend.Sync(ctx, 0)
		require.NoError(t, err)
		var records []*databroker.Record
		for stream.Next(false) {
			records = append(records, stream.Record())
		}
		_ = stream.Close()
		require.Len(t, records, 1000)

		backend.removeChangesBefore(time.Now().Add(time.Second))

		stream, err = backend.Sync(ctx, 0)
		require.NoError(t, err)
		records = nil
		for stream.Next(false) {
			records = append(records, stream.Record())
		}
		_ = stream.Close()
		require.Len(t, records, 0)

		return nil
	}))
}
