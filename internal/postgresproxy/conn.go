package postgresproxy

import (
	"bufio"
	"net"
)

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufferedConn(c net.Conn) *bufferedConn {
	return &bufferedConn{Conn: c, r: bufio.NewReader(c)}
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
