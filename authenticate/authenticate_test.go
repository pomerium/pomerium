package authenticate

import (
	"testing"

	"github.com/pomerium/pomerium/internal/config"
)

func newTestOptions(t *testing.T) *config.Options {
	opts, err := config.NewOptions("https://authenticate.example", "https://authorize.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	opts.ClientID = "client-id"
	opts.Provider = "google"
	opts.ClientSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw="
	opts.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw="
	return opts
}

func TestOptions_Validate(t *testing.T) {
	good := newTestOptions(t)
	badRedirectURL := newTestOptions(t)
	badRedirectURL.AuthenticateURL = nil
	badScheme := newTestOptions(t)
	badScheme.AuthenticateURL.Scheme = ""
	emptyClientID := newTestOptions(t)
	emptyClientID.ClientID = ""
	emptyClientSecret := newTestOptions(t)
	emptyClientSecret.ClientSecret = ""
	emptyCookieSecret := newTestOptions(t)
	emptyCookieSecret.CookieSecret = ""
	invalidCookieSecret := newTestOptions(t)
	invalidCookieSecret.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw^"
	shortCookieLength := newTestOptions(t)
	shortCookieLength.CookieSecret = "gN3xnvfsAwfCXxnJorGLKUG4l2wC8sS8nfLMhcStPg=="
	badSharedKey := newTestOptions(t)
	badSharedKey.SharedKey = ""
	badAuthenticateURL := newTestOptions(t)
	badAuthenticateURL.AuthenticateURL = nil

	tests := []struct {
		name    string
		o       *config.Options
		wantErr bool
	}{
		{"minimum options", good, false},
		{"nil options", &config.Options{}, true},
		{"bad redirect  url", badRedirectURL, true},
		{"bad scheme", badScheme, true},
		{"no cookie secret", emptyCookieSecret, true},
		{"invalid cookie secret", invalidCookieSecret, true},
		{"short cookie secret", shortCookieLength, true},
		{"no shared secret", badSharedKey, true},
		{"no client id", emptyClientID, true},
		{"no client secret", emptyClientSecret, true},
		{"empty authenticate url", badAuthenticateURL, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateOptions(*tt.o); (err != nil) != tt.wantErr {
				t.Errorf("Options.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
	good := newTestOptions(t)

	badRedirectURL := newTestOptions(t)
	badRedirectURL.AuthenticateURL = nil

	badCookieName := newTestOptions(t)
	badCookieName.CookieName = ""

	badProvider := newTestOptions(t)
	badProvider.Provider = ""

	tests := []struct {
		name string
		opts *config.Options
		// want    *Authenticate
		wantErr bool
	}{
		{"good", good, false},
		{"empty opts", &config.Options{}, true},
		{"fails to validate", badRedirectURL, true},
		{"bad cookie name", badCookieName, true},
		{"bad provider", badProvider, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(*tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
