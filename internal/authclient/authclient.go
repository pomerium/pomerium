// Package authclient contains an CLI authentication client for Pomerium.
package authclient

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/skratchdot/open-golang/open"
	"golang.org/x/sync/errgroup"
)

var openBrowser = open.Run

// An AuthClient retrieves an authentication JWT via the Pomerium login API.
type AuthClient struct {
	cfg *config
}

// New creates a new AuthClient.
func New(options ...Option) *AuthClient {
	return &AuthClient{
		cfg: getConfig(options...),
	}
}

// GetJWT retrieves a JWT from Pomerium.
func (client *AuthClient) GetJWT(ctx context.Context, serverURL *url.URL) (rawJWT string, err error) {
	li, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("failed to start listener: %w", err)
	}
	defer func() { _ = li.Close() }()

	incomingJWT := make(chan string)
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return client.runHTTPServer(ctx, li, incomingJWT)
	})
	eg.Go(func() error {
		return client.runOpenBrowser(ctx, li, serverURL)
	})
	eg.Go(func() error {
		select {
		case rawJWT = <-incomingJWT:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	})
	err = eg.Wait()
	if err != nil {
		return "", err
	}

	return rawJWT, nil
}

func (client *AuthClient) runHTTPServer(ctx context.Context, li net.Listener, incomingJWT chan string) error {
	var srv *http.Server
	srv = &http.Server{
		BaseContext: func(li net.Listener) context.Context {
			return ctx
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwt := r.FormValue("pomerium_jwt")
			if jwt == "" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			incomingJWT <- jwt

			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "login complete, you may close this page")

			go func() { _ = srv.Shutdown(ctx) }()
		}),
	}
	// shutdown the server when ctx is done.
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(ctx)
	}()
	err := srv.Serve(li)
	if err == http.ErrServerClosed {
		err = nil
	}
	return err
}

func (client *AuthClient) runOpenBrowser(ctx context.Context, li net.Listener, serverURL *url.URL) error {
	dst := serverURL.ResolveReference(&url.URL{
		Path: "/.pomerium/api/v1/login",
		RawQuery: url.Values{
			"pomerium_redirect_uri": {fmt.Sprintf("http://%s", li.Addr().String())},
		}.Encode(),
	})

	ctx, clearTimeout := context.WithTimeout(ctx, 10*time.Second)
	defer clearTimeout()

	req, err := http.NewRequestWithContext(ctx, "GET", dst.String(), nil)
	if err != nil {
		return err
	}

	transport := &http.Transport{
		TLSClientConfig: client.cfg.tlsConfig,
	}
	hc := &http.Client{
		Transport: transport,
	}

	res, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get login url: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode/100 != 2 {
		return fmt.Errorf("failed to get login url: %s", res.Status)
	}

	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read login url: %w", err)
	}

	return openBrowser(string(bs))
}
