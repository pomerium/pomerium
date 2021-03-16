package redis

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

func newClientFromURL(rawurl string, tlsConfig *tls.Config) (*redis.Client, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "redis", "rediss", "unix":
		opts, err := redis.ParseURL(rawurl)
		if err != nil {
			return nil, err
		}
		// when using TLS, the TLS config will not be set to nil, in which case we replace it with our own
		if opts.TLSConfig != nil {
			opts.TLSConfig = tlsConfig
		}
		return redis.NewClient(opts), nil

	case "redis-sentinel", "rediss-sentinel", "redis-sentinels":
		opts, err := ParseSentinelURL(rawurl)
		if err != nil {
			return nil, err
		}
		if opts.TLSConfig != nil {
			opts.TLSConfig = tlsConfig
		}
		return redis.NewFailoverClient(opts), nil

	default:
		return nil, fmt.Errorf("unsupported URL scheme: %s", u.Scheme)
	}
}

// ParseSentinelURL parses a redis-sentinel URL. Format is based on https://github.com/exponea/redis-sentinel-url:
//
//    redis+sentinel://[:password@]host:port[,host2:port2,...][/service_name[/db]][?param1=value1[&param2=value=2&...]]
//
// Additionally TLS is supported with rediss-sentinel, or redis-sentinels. Supported query params:
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

	if u.Scheme == "rediss-sentinel" || u.Scheme == "redis-sentinels" {
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
