package httputil

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHTTPServer(t *testing.T) {
	tests := []struct {
		name string
		opts *ServerOptions
		// wantErr bool
	}{
		{"localhost:9232", &ServerOptions{Addr: "localhost:9232"}},
		{"localhost:65536", &ServerOptions{Addr: "localhost:-1"}}, // will fail, but won't err
		{"empty", &ServerOptions{}},
		{"empty", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := NewHTTPServer(tt.opts, RedirectHandler())

			defer srv.Close()

			// we cheat a little bit here and use the httptest server to test the client
			ts := httptest.NewServer(srv.Handler)
			defer ts.Close()
			client := ts.Client()
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
			res, err := client.Get(ts.URL)
			if err != nil {
				log.Fatal(err)
			}
			greeting, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s", greeting)

		})
	}
}
