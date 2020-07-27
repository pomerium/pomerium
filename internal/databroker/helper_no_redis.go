// +build !redis

package databroker

func newTestServer() *Server {
	return New()
}
