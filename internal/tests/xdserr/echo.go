package xdserr

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"golang.org/x/sync/errgroup"
)

func echo(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, "pong")
}

// RunEcho runs a test echo http server
func RunEcho(ctx context.Context) (string, error) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return "", err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", echo)
	srv := http.Server{
		Handler: mux,
	}
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return srv.Serve(l) })
	eg.Go(func() error {
		<-ctx.Done()
		return srv.Close()
	})
	return l.Addr().String(), nil
}
