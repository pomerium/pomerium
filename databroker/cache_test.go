package databroker

import (
	"context"
	"testing"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		opts    config.Options
		wantErr bool
	}{
		{"good", config.Options{SharedKey: cryptutil.NewBase64Key(), DataBrokerURLString: "http://example"}, false},
		{"bad shared secret", config.Options{SharedKey: string([]byte(cryptutil.NewBase64Key())[:31]), DataBrokerURLString: "http://example"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.Provider = "google"
			_, err := New(context.Background(), &config.Config{Options: &tt.opts}, events.New())
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
