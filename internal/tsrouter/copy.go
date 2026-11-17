package tsrouter

import (
	"errors"
	"io"
	"net"
)

var errCopyDone = errors.New("copy done")

func copyFull(conn1, conn2 net.Conn) error {
	// this code is largely taken from httputil.ReverseProxy
	errc := make(chan error, 1)

	go func() { errc <- copyHalf(conn1, conn2) }()
	go func() { errc <- copyHalf(conn2, conn1) }()

	// Wait until both copy functions have sent on the error channel,
	// or until one fails.
	err := <-errc
	if err == nil {
		err = <-errc
	}
	return err
}

func copyHalf(dst, src io.ReadWriter) error {
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}

	if wc, ok := dst.(interface{ CloseWrite() error }); ok {
		return wc.CloseWrite()
	}

	return errCopyDone
}
