package redis

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"sync"

	"github.com/gomodule/redigo/redis"
)

var pathDBRegexp = regexp.MustCompile(`/(\d*)\z`)

// this function was taken from redis.DialURL to support context.
func dialURL(ctx context.Context, rawurl string, options ...redis.DialOption) (redis.Conn, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "redis" && u.Scheme != "rediss" {
		return nil, fmt.Errorf("invalid redis URL scheme: %s", u.Scheme)
	}

	if u.Opaque != "" {
		return nil, fmt.Errorf("invalid redis URL, url is opaque: %s", rawurl)
	}

	// As per the IANA draft spec, the host defaults to localhost and
	// the port defaults to 6379.
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		// assume port is missing
		host = u.Host
		port = "6379"
	}
	if host == "" {
		host = "localhost"
	}
	address := net.JoinHostPort(host, port)

	if u.User != nil {
		password, isSet := u.User.Password()
		if isSet {
			options = append(options, redis.DialUsername(u.User.Username()), redis.DialPassword(password))
		}
	}

	match := pathDBRegexp.FindStringSubmatch(u.Path)
	if len(match) == 2 {
		db := 0
		if len(match[1]) > 0 {
			db, err = strconv.Atoi(match[1])
			if err != nil {
				return nil, fmt.Errorf("invalid database: %s", u.Path[1:])
			}
		}
		if db != 0 {
			options = append(options, redis.DialDatabase(db))
		}
	} else if u.Path != "" {
		return nil, fmt.Errorf("invalid database: %s", u.Path[1:])
	}

	options = append(options, redis.DialUseTLS(u.Scheme == "rediss"))

	return redis.DialContext(ctx, "tcp", address, options...)
}

type pubSubConn struct {
	tracker *pubSubTracker
	redis.Conn

	closeOnce sync.Once
	closeErr  error
}

func newPubSubConn(tracker *pubSubTracker, conn redis.Conn) redis.Conn {
	tracker.Lock()
	tracker.active++
	tracker.Unlock()
	return &pubSubConn{
		tracker: tracker,
		Conn:    conn,
	}
}

func (conn *pubSubConn) Close() error {
	conn.closeOnce.Do(func() {
		conn.tracker.Lock()
		conn.tracker.active--
		conn.tracker.Unlock()
		conn.closeErr = conn.Conn.Close()
	})
	return conn.closeErr
}

type pubSubTracker struct {
	db *DB

	sync.Mutex
	active int
}

func newPubSubTracker(db *DB) *pubSubTracker {
	return &pubSubTracker{
		db: db,
	}
}

func (tracker *pubSubTracker) ActiveCount() int {
	tracker.Lock()
	defer tracker.Unlock()
	return tracker.active
}

func (tracker *pubSubTracker) Get(ctx context.Context) (*redis.PubSubConn, error) {
	conn, err := tracker.db.dial(ctx)
	if err != nil {
		return nil, err
	}
	return &redis.PubSubConn{
		Conn: newPubSubConn(tracker, conn),
	}, nil
}
