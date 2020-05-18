package authenticate

import (
	"testing"

	"github.com/pomerium/pomerium/config"
)

func newTestOptions(t *testing.T) *config.Options {

	opts := config.NewDefaultOptions()
	opts.AuthenticateURLString = "https://authenticate.example"
	opts.AuthorizeURLString = "https://authorize.example"
	opts.InsecureServer = true
	opts.ClientID = "client-id"
	opts.Provider = "google"
	opts.ClientSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw="
	opts.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw="
	err := opts.Validate()
	if err != nil {
		t.Fatal(err)
	}
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
	badCallbackPath := newTestOptions(t)
	badCallbackPath.AuthenticateCallbackPath = ""

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
		{"empty callback path", badCallbackPath, true},
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
	good.CookieName = "A"

	badRedirectURL := newTestOptions(t)
	badRedirectURL.AuthenticateURL = nil
	badRedirectURL.CookieName = "B"

	badCookieName := newTestOptions(t)
	badCookieName.CookieName = ""

	badProvider := newTestOptions(t)
	badProvider.Provider = ""
	badProvider.CookieName = "C"
	badGRPCConn := newTestOptions(t)
	badGRPCConn.CacheURL = nil
	badGRPCConn.CookieName = "D"

	emptyProviderURL := newTestOptions(t)
	emptyProviderURL.Provider = "oidc"
	emptyProviderURL.ProviderURL = ""

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
		{"bad cache url", badGRPCConn, true},
		{"empty provider url", emptyProviderURL, true},
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
