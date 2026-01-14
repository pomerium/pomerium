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
	opts.SigningKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUJlMFRxbXJkSXBZWE03c3pSRERWYndXOS83RWJHVWhTdFFJalhsVHNXM1BvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFb0xaRDI2bEdYREhRQmhhZkdlbEVmRDdlNmYzaURjWVJPVjdUbFlIdHF1Y1BFL2hId2dmYQpNY3FBUEZsRmpueUpySXJhYTFlQ2xZRTJ6UktTQk5kNXBRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="

	err := opts.Validate()
	if err != nil {
		t.Fatal(err)
	}
	return opts
}

func TestOptions_Validate(t *testing.T) {
	t.Parallel()

	good := newTestOptions(t)
	badScheme := newTestOptions(t)
	badScheme.AuthenticateURLString = "BAD_SCHEME://"
	emptyClientID := newTestOptions(t)
	emptyClientID.ClientID = ""
	emptyClientSecret := newTestOptions(t)
	emptyClientSecret.ClientSecret = ""
	invalidCookieSecret := newTestOptions(t)
	invalidCookieSecret.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw^"
	shortCookieLength := newTestOptions(t)
	shortCookieLength.CookieSecret = "gN3xnvfsAwfCXxnJorGLKUG4l2wC8sS8nfLMhcStPg=="
	badSharedKey := newTestOptions(t)
	badSharedKey.Services = "authenticate"
	badSharedKey.SharedKey = ""
	badAuthenticateURL := newTestOptions(t)
	badAuthenticateURL.AuthenticateURLString = "BAD_URL"

	tests := []struct {
		name    string
		o       *config.Options
		wantErr bool
	}{
		{"minimum options", good, false},
		{"nil options", &config.Options{}, true},
		{"invalid cookie secret", invalidCookieSecret, true},
		{"short cookie secret", shortCookieLength, true},
		{"no shared secret", badSharedKey, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := ValidateOptions(tt.o); (err != nil) != tt.wantErr {
				t.Errorf("Options.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	good := newTestOptions(t)
	good.CookieName = "A"

	badRedirectURL := newTestOptions(t)
	badRedirectURL.AuthenticateURLString = "BAD URL"
	badRedirectURL.CookieName = "B"

	badProvider := newTestOptions(t)
	badProvider.Provider = ""
	badProvider.CookieName = "C"
	badGRPCConn := newTestOptions(t)
	badGRPCConn.CookieName = "D"
	badGRPCConn.DataBroker.ServiceURL = "BAD"

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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := New(t.Context(), &config.Config{Options: tt.opts})
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
