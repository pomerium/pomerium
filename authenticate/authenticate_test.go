package authenticate

import (
	"net/url"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/config"
)

func testOptions() config.Options {
	redirectURL, _ := url.Parse("https://example.com/oauth2/callback")
	return config.Options{
		AuthenticateURL: *redirectURL,
		SharedKey:       "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ=",
		ClientID:        "test-client-id",
		ClientSecret:    "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw=",
		CookieSecret:    "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw=",
		CookieRefresh:   time.Duration(1) * time.Hour,
		CookieExpire:    time.Duration(168) * time.Hour,
		CookieName:      "pomerium",
	}
}

func TestOptions_Validate(t *testing.T) {
	good := testOptions()
	badRedirectURL := testOptions()
	badRedirectURL.AuthenticateURL = url.URL{}
	emptyClientID := testOptions()
	emptyClientID.ClientID = ""
	emptyClientSecret := testOptions()
	emptyClientSecret.ClientSecret = ""
	emptyCookieSecret := testOptions()
	emptyCookieSecret.CookieSecret = ""
	invalidCookieSecret := testOptions()
	invalidCookieSecret.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw^"
	shortCookieLength := testOptions()
	shortCookieLength.CookieSecret = "gN3xnvfsAwfCXxnJorGLKUG4l2wC8sS8nfLMhcStPg=="
	badSharedKey := testOptions()
	badSharedKey.SharedKey = ""
	badAuthenticateURL := testOptions()
	badAuthenticateURL.AuthenticateURL = url.URL{}

	tests := []struct {
		name    string
		o       config.Options
		wantErr bool
	}{
		{"minimum options", good, false},
		{"nil options", config.Options{}, true},
		{"bad redirect  url", badRedirectURL, true},
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
			o := tt.o
			if err := ValidateOptions(o); (err != nil) != tt.wantErr {
				t.Errorf("Options.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
	good := testOptions()
	good.Provider = "google"

	badRedirectURL := testOptions()
	badRedirectURL.AuthenticateURL = url.URL{}

	tests := []struct {
		name string
		opts config.Options
		// want    *Authenticate
		wantErr bool
	}{
		{"good", good, false},
		{"empty opts", config.Options{}, true},
		{"fails to validate", badRedirectURL, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// if !reflect.DeepEqual(got, tt.want) {
			// 	t.Errorf("New() = %v, want %v", got, tt.want)
			// }
		})
	}
}
