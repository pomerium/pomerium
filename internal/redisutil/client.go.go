package redisutil

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/scylladb/go-set"
)

var (
	standardSchemes = set.NewStringSet("redis", "rediss", "unix")
	clusterSchemes  = set.NewStringSet(
		"redis+cluster", "redis-cluster",
		"rediss+cluster", "rediss-cluster",
		"redis+clusters", "redis-clusters",
	)
	sentinelSchemes = set.NewStringSet(
		"redis+sentinel", "redis-sentinel",
		"rediss+sentinel", "rediss-sentinel",
		"redis+sentinels", "redis-sentinels",
	)
	sentinelClusterSchemes = set.NewStringSet(
		"redis+sentinel+cluster", "redis-sentinel-cluster",
		"rediss+sentinel+cluster", "rediss-sentinel-cluster",
		"redis+sentinels+cluster", "redis-sentinels-cluster",
		"redis+sentinel+clusters", "redis-sentinel-clusters",
	)
	tlsSchemes = set.NewStringSet(
		"rediss",
		"rediss+cluster", "rediss-cluster",
		"redis+clusters", "redis-clusters",
		"rediss+sentinel", "rediss-sentinel",
		"redis+sentinels", "redis-sentinels",
		"rediss+sentinel+cluster", "rediss-sentinel-cluster",
		"redis+sentinels+cluster", "redis-sentinels-cluster",
		"redis+sentinel+clusters", "redis-sentinel-clusters",
	)
)

// NewClientFromURL creates a new redis client by parsing the raw URL.
func NewClientFromURL(rawURL string, tlsConfig *tls.Config) (redis.UniversalClient, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	switch {
	case standardSchemes.Has(u.Scheme):
		opts, err := redis.ParseURL(rawURL)
		if err != nil {
			return nil, err
		}
		// when using TLS, the TLS config will not be set to nil, in which case we replace it with our own
		if opts.TLSConfig != nil {
			opts.TLSConfig = tlsConfig
		}
		return redis.NewClient(opts), nil

	case clusterSchemes.Has(u.Scheme):
		opts, err := ParseClusterURL(rawURL)
		if err != nil {
			return nil, err
		}
		if opts.TLSConfig != nil {
			opts.TLSConfig = tlsConfig
		}
		return redis.NewClusterClient(opts), nil

	case sentinelSchemes.Has(u.Scheme):
		opts, err := ParseSentinelURL(rawURL)
		if err != nil {
			return nil, err
		}
		if opts.TLSConfig != nil {
			opts.TLSConfig = tlsConfig
		}
		return redis.NewFailoverClient(opts), nil

	case sentinelClusterSchemes.Has(u.Scheme):
		opts, err := ParseSentinelURL(rawURL)
		if err != nil {
			return nil, err
		}
		if opts.TLSConfig != nil {
			opts.TLSConfig = tlsConfig
		}
		return redis.NewFailoverClusterClient(opts), nil

	default:
		return nil, fmt.Errorf("unsupported URL scheme: %s", u.Scheme)
	}
}

// ParseClusterURL parses a redis-cluster URL. Format is:
//
//    redis+cluster://[username:password@]host:port[,host2:port2,...]/[?param1=value1[&param2=value=2&...]]
//
// Additionally TLS is supported with rediss+cluster, or redis+clusters. Supported query params:
//
//    max_redirects: int
//    read_only: bool
//    route_by_latency: bool
//    route_randomly: bool
//    max_retries: int
//    min_retry_backoff: duration
//    max_retry_backoff: duration
//    dial_timeout: duration
//    read_timeout: duration
//    write_timeout: duration
//    pool_size: int
//    min_idle_conns: int
//    max_conn_age: duration
//    pool_timeout: duration
//    idle_timeout: duration
//    idle_check_frequency: duration
//
func ParseClusterURL(rawurl string) (*redis.ClusterOptions, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	opts := new(redis.ClusterOptions)

	hostParts := strings.Split(u.Host, ",")
	for _, hostPart := range hostParts {
		host, port, err := net.SplitHostPort(hostPart)
		if err != nil {
			host = hostPart
			port = "6379"
		}
		opts.Addrs = append(opts.Addrs,
			net.JoinHostPort(host, port))
	}

	q := u.Query()
	if err := parseIntParam(&opts.MaxRedirects, q, "max_redirects"); err != nil {
		return nil, err
	}
	if err := parseBoolParam(&opts.ReadOnly, q, "read_only"); err != nil {
		return nil, err
	}
	if err := parseBoolParam(&opts.RouteByLatency, q, "route_by_latency"); err != nil {
		return nil, err
	}
	if err := parseBoolParam(&opts.RouteRandomly, q, "route_randomly"); err != nil {
		return nil, err
	}
	if ui := u.User; ui != nil {
		opts.Username = ui.Username()
		opts.Password, _ = ui.Password()
	}
	if err := parseIntParam(&opts.MaxRetries, q, "max_retries"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.MinRetryBackoff, q, "min_retry_backoff"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.MaxRetryBackoff, q, "max_retry_backoff"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.DialTimeout, q, "dial_timeout"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.ReadTimeout, q, "read_timeout"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.WriteTimeout, q, "write_timeout"); err != nil {
		return nil, err
	}
	if err := parseIntParam(&opts.PoolSize, q, "pool_size"); err != nil {
		return nil, err
	}
	if err := parseIntParam(&opts.MinIdleConns, q, "min_idle_conns"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.MaxConnAge, q, "max_conn_age"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.PoolTimeout, q, "pool_timeout"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.IdleTimeout, q, "idle_timeout"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.IdleCheckFrequency, q, "idle_check_frequency"); err != nil {
		return nil, err
	}

	if tlsSchemes.Has(u.Scheme) {
		opts.TLSConfig = &tls.Config{} //nolint
	}

	return opts, nil
}

// ParseSentinelURL parses a redis-sentinel URL. Format is based on https://github.com/exponea/redis-sentinel-url:
//
//    redis+sentinel://[:password@]host:port[,host2:port2,...][/service_name[/db]][?param1=value1[&param2=value=2&...]]
//
// Additionally TLS is supported with rediss+sentinel, or redis+sentinels. Supported query params:
//
//    slave_only: bool
//    use_disconnected_slaves: bool
//    query_sentinel_randomly: bool
//    username: string (username for redis connection)
//    password: string (password for redis connection)
//    max_retries: int
//    min_retry_backoff: duration
//    max_retry_backoff: duration
//    dial_timeout: duration
//    read_timeout: duration
//    write_timeout: duration
//    pool_size: int
//    min_idle_conns: int
//    max_conn_age: duration
//    pool_timeout: duration
//    idle_timeout: duration
//    idle_check_frequency: duration
//
func ParseSentinelURL(rawurl string) (*redis.FailoverOptions, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	opts := new(redis.FailoverOptions)

	pathParts := strings.Split(u.Path, "/")
	if len(pathParts) > 1 {
		opts.MasterName = pathParts[1]
	}
	if len(pathParts) > 2 {
		opts.DB, err = strconv.Atoi(pathParts[2])
		if err != nil {
			return nil, fmt.Errorf("invalid database: %w", err)
		}
	}

	hostParts := strings.Split(u.Host, ",")
	for _, hostPart := range hostParts {
		host, port, err := net.SplitHostPort(hostPart)
		if err != nil {
			host = hostPart
			port = "26379" // "By default Sentinel runs using TCP port 26379"
		}
		opts.SentinelAddrs = append(opts.SentinelAddrs,
			net.JoinHostPort(host, port))
	}

	if u.User != nil {
		opts.SentinelPassword, _ = u.User.Password()
	}

	q := u.Query()
	if err := parseBoolParam(&opts.SlaveOnly, q, "slave_only"); err != nil {
		return nil, err
	}
	if err := parseBoolParam(&opts.RouteByLatency, q, "route_by_latency"); err != nil {
		return nil, err
	}
	if err := parseBoolParam(&opts.RouteRandomly, q, "route_randomly"); err != nil {
		return nil, err
	}
	if err := parseBoolParam(&opts.UseDisconnectedSlaves, q, "use_disconnected_slaves"); err != nil {
		return nil, err
	}
	if err := parseBoolParam(&opts.QuerySentinelRandomly, q, "query_sentinel_randomly"); err != nil {
		return nil, err
	}
	opts.Username = q.Get("username")
	opts.Password = q.Get("password")
	if err := parseIntParam(&opts.MaxRetries, q, "max_retries"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.MinRetryBackoff, q, "min_retry_backoff"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.MaxRetryBackoff, q, "max_retry_backoff"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.DialTimeout, q, "dial_timeout"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.ReadTimeout, q, "read_timeout"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.WriteTimeout, q, "write_timeout"); err != nil {
		return nil, err
	}
	if err := parseIntParam(&opts.PoolSize, q, "pool_size"); err != nil {
		return nil, err
	}
	if err := parseIntParam(&opts.MinIdleConns, q, "min_idle_conns"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.MaxConnAge, q, "max_conn_age"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.PoolTimeout, q, "pool_timeout"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.IdleTimeout, q, "idle_timeout"); err != nil {
		return nil, err
	}
	if err := parseDurationParam(&opts.IdleCheckFrequency, q, "idle_check_frequency"); err != nil {
		return nil, err
	}

	if tlsSchemes.Has(u.Scheme) {
		opts.TLSConfig = &tls.Config{} //nolint
	}

	return opts, nil
}

func parseBoolParam(dst *bool, values url.Values, name string) error {
	v := values.Get(name)
	if v == "" {
		return nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	*dst = b
	return nil
}

func parseIntParam(dst *int, values url.Values, name string) error {
	v := values.Get(name)
	if v == "" {
		return nil
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	*dst = i
	return nil
}

func parseDurationParam(dst *time.Duration, values url.Values, name string) error {
	v := values.Get(name)
	if v == "" {
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	*dst = d
	return nil
}
