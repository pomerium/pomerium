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
	badCallbackPath := newTestOptions(t)
	badCallbackPath.AuthenticateCallbackPath = ""

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
		{"empty callback path", badCallbackPath, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateOptions(tt.o); (err != nil) != tt.wantErr {
				t.Errorf("Options.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
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

	goodSigningKey := newTestOptions(t)
	goodSigningKey.SigningKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUpCMFZkbko1VjEvbVlpYUlIWHhnd2Q0Yzd5YWRTeXMxb3Y0bzA1b0F3ekdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFVUc1eENQMEpUVDFINklvbDhqS3VUSVBWTE0wNENnVzlQbEV5cE5SbVdsb29LRVhSOUhUMwpPYnp6aktZaWN6YjArMUt3VjJmTVRFMTh1dy82MXJVQ0JBPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="

	badSigningKey := newTestOptions(t)
	badSigningKey.SigningKey = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJFakNCdWdJSkFNWUdtVzhpYWd1TU1Bb0dDQ3FHU000OUJBTUNNQkV4RHpBTkJnTlZCQU1NQm5WdWRYTmwKWkRBZ0Z3MHlNREExTWpJeU1EUTFNalJhR0E4ME56VTRNRFF4T1RJd05EVXlORm93RVRFUE1BMEdBMVVFQXd3RwpkVzUxYzJWa01Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRVVHNXhDUDBKVFQxSDZJb2w4akt1ClRJUFZMTTA0Q2dXOVBsRXlwTlJtV2xvb0tFWFI5SFQzT2J6empLWWljemIwKzFLd1YyZk1URTE4dXcvNjFyVUMKQkRBS0JnZ3Foa2pPUFFRREFnTkhBREJFQWlBSFFDUFh2WG5oeHlDTGNhZ3N3eWt4RUM1NFV5RmdyUVJVRmVCYwpPUzVCSFFJZ1Y3T2FXY2pMeHdsRlIrWDZTQ2daZDI5bXBtOVZKNnpXQURhWGdEN3FURW89Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"

	tests := []struct {
		name string
		opts *config.Options
		// want    *Authenticate
		wantErr bool
	}{
		{"good", good, false},
		{"empty opts", &config.Options{}, true},
		{"fails to validate", badRedirectURL, true},
		{"good signing key", goodSigningKey, false},
		{"bad signing key", badSigningKey, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(t.Context(), &config.Config{Options: tt.opts})
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
