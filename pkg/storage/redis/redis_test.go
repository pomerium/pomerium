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

	"github.com/gomodule/redigo/redis"
	"github.com/ory/dockertest/v3"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

var db *DB

func cleanup(c redis.Conn, db *DB, t *testing.T) {
	require.NoError(t, c.Send("MULTI"))
	require.NoError(t, c.Send("DEL", db.recordType))
	require.NoError(t, c.Send("DEL", db.versionSet))
	require.NoError(t, c.Send("DEL", db.deletedSet))
	_, err := c.Do("EXEC")
	require.NoError(t, err)
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

func runWithRedisDockerImage(repo, tag string, env []string, withTLS bool, testFunc func(t *testing.T), t *testing.T) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to docker: %s", err)
	}
	resource, err := pool.Run(repo, tag, env)
	if err != nil {
		t.Fatalf("Could not start resource: %s", err)
	}

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
		db, err = New(address, "record_type", int64(time.Hour.Seconds()), WithTLSConfig(tlsConfig(address, t)))
		if err != nil {
			return err
		}
		_, err = db.pool.Get().Do("PING")
		return err
	}); err != nil {
		t.Fatalf("Could not connect to docker: %s", err)
	}

	testFunc(t)
}

func TestDB(t *testing.T) {
	redisTLSEnv := []string{
		"ALLOW_EMPTY_PASSWORD=yes",
		"REDIS_TLS_ENABLED=yes",
		"REDIS_TLS_CERT_FILE=/tls/redis.crt",
		"REDIS_TLS_KEY_FILE=/tls/redis.key",
		"REDIS_TLS_CA_FILE=/tls/ca.crt",
	}
	tests := []struct {
		name    string
		repo    string
		tag     string
		env     []string
		withTLS bool
	}{
		{"redis", "redis", "latest", nil, false},
		{"redis TLS", "gnouc/pomerium-redis-tls", "latest", redisTLSEnv, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runWithRedisDockerImage(tc.repo, tc.tag, tc.env, tc.withTLS, testDB, t)
		})
	}
}

func testDB(t *testing.T) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	ids := []string{"a", "b", "c"}
	id := ids[0]
	c := db.pool.Get()
	defer c.Close()

	ch := db.Watch(ctx)

	t.Run("get missing record", func(t *testing.T) {
		record, err := db.Get(ctx, id)
		assert.Error(t, err)
		assert.Nil(t, record)
	})
	t.Run("get record", func(t *testing.T) {
		data := new(anypb.Any)
		assert.NoError(t, db.Put(ctx, id, data))
		record, err := db.Get(ctx, id)
		require.NoError(t, err)
		if assert.NotNil(t, record) {
			assert.NotNil(t, record.CreatedAt)
			assert.Equal(t, data, record.Data)
			assert.Nil(t, record.DeletedAt)
			assert.Equal(t, "a", record.Id)
			assert.NotNil(t, record.ModifiedAt)
			assert.Equal(t, "000000000001", record.Version)
		}
	})
	t.Run("delete record", func(t *testing.T) {
		assert.NoError(t, db.Delete(ctx, id))
		record, err := db.Get(ctx, id)
		require.NoError(t, err)
		require.NotNil(t, record)
		assert.NotNil(t, record.DeletedAt)
	})
	t.Run("clear deleted", func(t *testing.T) {
		db.ClearDeleted(ctx, time.Now().Add(time.Second))
		record, err := db.Get(ctx, id)
		assert.Error(t, err)
		assert.Nil(t, record)
	})
	t.Run("get all", func(t *testing.T) {
		records, err := db.GetAll(ctx)
		assert.NoError(t, err)
		assert.Len(t, records, 0)
		data := new(anypb.Any)

		for _, id := range ids {
			assert.NoError(t, db.Put(ctx, id, data))
		}
		records, err = db.GetAll(ctx)
		assert.NoError(t, err)
		assert.Len(t, records, len(ids))
		for _, id := range ids {
			_, _ = c.Do("DEL", id)
		}
	})
	t.Run("list", func(t *testing.T) {
		cleanup(c, db, t)

		for i := 0; i < 10; i++ {
			id := fmt.Sprintf("%02d", i)
			data := new(anypb.Any)
			assert.NoError(t, db.Put(ctx, id, data))
		}

		records, err := db.List(ctx, "")
		assert.NoError(t, err)
		assert.Len(t, records, 10)
		records, err = db.List(ctx, "00000000000A")
		assert.NoError(t, err)
		assert.Len(t, records, 5)
		records, err = db.List(ctx, "00000000000F")
		assert.NoError(t, err)
		assert.Len(t, records, 0)
	})

	expectedNumEvents := 14
	actualNumEvents := 0
	for range ch {
		actualNumEvents++
		if actualNumEvents == expectedNumEvents {
			cancelFunc()
		}
	}
}
