package authenticate

import (
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"
)

func init() {
	os.Clearenv()
}

func testOptions() *Options {
	redirectURL, _ := url.Parse("https://example.com/oauth2/callback")
	return &Options{
		ProxyRootDomains:   []string{"example.com"},
		AllowedDomains:     []string{"example.com"},
		RedirectURL:        redirectURL,
		SharedKey:          "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ=",
		ClientID:           "test-client-id",
		ClientSecret:       "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw=",
		CookieSecret:       "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw=",
		CookieRefresh:      time.Duration(1) * time.Hour,
		SessionLifetimeTTL: time.Duration(720) * time.Hour,
		CookieExpire:       time.Duration(168) * time.Hour,
	}
}

func TestOptions_Validate(t *testing.T) {
	good := testOptions()
	badRedirectURL := testOptions()
	badRedirectURL.RedirectURL = nil
	malformedRedirectURL := testOptions()
	redirectURL, _ := url.Parse("https://example.com/oauth3/callback")
	malformedRedirectURL.RedirectURL = redirectURL
	emptyClientID := testOptions()
	emptyClientID.ClientID = ""
	emptyClientSecret := testOptions()
	emptyClientSecret.ClientSecret = ""
	allowedDomains := testOptions()
	allowedDomains.AllowedDomains = nil
	proxyRootDomains := testOptions()
	proxyRootDomains.ProxyRootDomains = nil
	emptyCookieSecret := testOptions()
	emptyCookieSecret.CookieSecret = ""
	invalidCookieSecret := testOptions()
	invalidCookieSecret.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw^"
	shortCookieLength := testOptions()
	shortCookieLength.CookieSecret = "gN3xnvfsAwfCXxnJorGLKUG4l2wC8sS8nfLMhcStPg=="
	badSharedKey := testOptions()
	badSharedKey.SharedKey = ""

	tests := []struct {
		name    string
		o       *Options
		wantErr bool
	}{
		{"minimum options", good, false},
		{"nil options", &Options{}, true},
		{"bad redirect  url", badRedirectURL, true},
		{"malformed redirect url", malformedRedirectURL, true},
		{"no cookie secret", emptyCookieSecret, true},
		{"invalid cookie secret", invalidCookieSecret, true},
		{"short cookie secret", shortCookieLength, true},
		{"no shared secret", badSharedKey, true},
		{"no client id", emptyClientID, true},
		{"no client secret", emptyClientSecret, true},
		{"empty allowed domains", allowedDomains, true},
		{"empty root domains", proxyRootDomains, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := tt.o
			if err := o.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Options.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOptionsFromEnvConfig(t *testing.T) {
	tests := []struct {
		name     string
		want     *Options
		envKey   string
		envValue string
		wantErr  bool
	}{
		{"good default, no env settings", defaultOptions, "", "", false},
		{"bad url", nil, "REDIRECT_URL", "%.rjlw", true},
		{"good duration", defaultOptions, "COOKIE_EXPIRE", "1m", false},
		{"bad duration", nil, "COOKIE_EXPIRE", "1sm", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envKey != "" {
				os.Setenv(tt.envKey, tt.envValue)
				defer os.Unsetenv(tt.envKey)
			}
			got, err := OptionsFromEnvConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("OptionsFromEnvConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("OptionsFromEnvConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_dotPrependDomains(t *testing.T) {

	tests := []struct {
		name string
		d    []string
		want []string
	}{
		{"single domain", []string{"google.com"}, []string{".google.com"}},
		{"multiple domain", []string{"google.com", "bing.com"}, []string{".google.com", ".bing.com"}},
		{"empty", []string{""}, []string{""}},
		{"nested subdomain", []string{"some.really.long.domain.com"}, []string{".some.really.long.domain.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dotPrependDomains(tt.d); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("dotPrependDomains() = %v, want %v", got, tt.want)
			}
		})
	}
}
