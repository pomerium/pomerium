package redisutil

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseClusterURL(t *testing.T) {
	opts, err := ParseClusterURL("redis+cluster://CLUSTER_USERNAME:CLUSTER_PASSWORD@localhost:26379,otherhost:26479/?" + (&url.Values{
		"read_only":            {"true"},
		"username":             {"USERNAME"},
		"password":             {"PASSWORD"},
		"max_retries":          {"11"},
		"min_retry_backoff":    {"31s"},
		"max_retry_backoff":    {"22m"},
		"dial_timeout":         {"3m"},
		"read_timeout":         {"4m"},
		"write_timeout":        {"5m"},
		"pool_size":            {"7"},
		"min_idle_conns":       {"2"},
		"max_conn_age":         {"1h"},
		"pool_timeout":         {"30m"},
		"idle_timeout":         {"31m"},
		"idle_check_frequency": {"32m"},
	}).Encode())
	require.NoError(t, err)
	assert.Equal(t, []string{"localhost:26379", "otherhost:26479"}, opts.Addrs)
	assert.Equal(t, "CLUSTER_USERNAME", opts.Username)
	assert.Equal(t, "CLUSTER_PASSWORD", opts.Password)
	assert.True(t, opts.ReadOnly)
	assert.Equal(t, 11, opts.MaxRetries)
	assert.Equal(t, time.Second*31, opts.MinRetryBackoff)
	assert.Equal(t, time.Minute*22, opts.MaxRetryBackoff)
	assert.Equal(t, time.Minute*3, opts.DialTimeout)
	assert.Equal(t, time.Minute*4, opts.ReadTimeout)
	assert.Equal(t, time.Minute*5, opts.WriteTimeout)
	assert.Equal(t, 7, opts.PoolSize)
	assert.Equal(t, 2, opts.MinIdleConns)
	assert.Equal(t, time.Hour, opts.MaxConnAge)
	assert.Equal(t, time.Minute*30, opts.PoolTimeout)
	assert.Equal(t, time.Minute*31, opts.IdleTimeout)
	assert.Equal(t, time.Minute*32, opts.IdleCheckFrequency)
}

func TestParseSentinelURL(t *testing.T) {
	opts, err := ParseSentinelURL("redis+sentinel://:SENTINEL_PASSWORD@localhost:26379,otherhost:26479/mymaster/3?" + (&url.Values{
		"slave_only":              {"true"},
		"use_disconnected_slaves": {"T"},
		"query_sentinel_randomly": {"1"},
		"username":                {"USERNAME"},
		"password":                {"PASSWORD"},
		"max_retries":             {"11"},
		"min_retry_backoff":       {"31s"},
		"max_retry_backoff":       {"22m"},
		"dial_timeout":            {"3m"},
		"read_timeout":            {"4m"},
		"write_timeout":           {"5m"},
		"pool_size":               {"7"},
		"min_idle_conns":          {"2"},
		"max_conn_age":            {"1h"},
		"pool_timeout":            {"30m"},
		"idle_timeout":            {"31m"},
		"idle_check_frequency":    {"32m"},
	}).Encode())
	require.NoError(t, err)
	assert.Equal(t, "mymaster", opts.MasterName)
	assert.Equal(t, []string{"localhost:26379", "otherhost:26479"}, opts.SentinelAddrs)
	assert.Equal(t, "SENTINEL_PASSWORD", opts.SentinelPassword)
	assert.True(t, opts.SlaveOnly)
	assert.True(t, opts.UseDisconnectedSlaves)
	assert.True(t, opts.QuerySentinelRandomly)
	assert.Equal(t, "USERNAME", opts.Username)
	assert.Equal(t, "PASSWORD", opts.Password)
	assert.Equal(t, 3, opts.DB)
	assert.Equal(t, 11, opts.MaxRetries)
	assert.Equal(t, time.Second*31, opts.MinRetryBackoff)
	assert.Equal(t, time.Minute*22, opts.MaxRetryBackoff)
	assert.Equal(t, time.Minute*3, opts.DialTimeout)
	assert.Equal(t, time.Minute*4, opts.ReadTimeout)
	assert.Equal(t, time.Minute*5, opts.WriteTimeout)
	assert.Equal(t, 7, opts.PoolSize)
	assert.Equal(t, 2, opts.MinIdleConns)
	assert.Equal(t, time.Hour, opts.MaxConnAge)
	assert.Equal(t, time.Minute*30, opts.PoolTimeout)
	assert.Equal(t, time.Minute*31, opts.IdleTimeout)
	assert.Equal(t, time.Minute*32, opts.IdleCheckFrequency)
}
