package cache

import (
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"testing"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestNew(t *testing.T) {
	dir, err := ioutil.TempDir("", "example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	tests := []struct {
		name    string
		opts    config.Options
		wantErr bool
	}{
		{"good", config.Options{SharedKey: cryptutil.NewBase64Key(), DataBrokerURL: &url.URL{Scheme: "http", Host: "example"}}, false},
		{"bad shared secret", config.Options{SharedKey: string([]byte(cryptutil.NewBase64Key())[:31]), DataBrokerURL: &url.URL{Scheme: "http", Host: "example"}}, true},
		{"bad cache url", config.Options{SharedKey: cryptutil.NewBase64Key(), DataBrokerURL: &url.URL{}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.Provider = "google"
			_, err := New(&config.Config{Options: &tt.opts})
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
