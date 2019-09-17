package urlutil

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_StripPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		hostport string
		want     string
	}{
		{"localhost", "localhost", "localhost"},
		{"localhost with port", "localhost:443", "localhost"},
		{"IPv6 localhost", "[::1]:80", "::1"},
		{"IPv6 localhost without port", "[::1]", "::1"},
		{"domain with port", "example.org:8080", "example.org"},
		{"domain without port", "example.org", "example.org"},
		{"long domain with port", "some.super.long.domain.example.org:8080", "some.super.long.domain.example.org"},
		{"IPv6 with port", "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:17000", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{"IPv6 without port", "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripPort(tt.hostport); got != tt.want {
				t.Errorf("StripPort() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseAndValidateURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		rawurl  string
		want    *url.URL
		wantErr bool
	}{
		{"good", "https://some.example", &url.URL{Scheme: "https", Host: "some.example"}, false},
		{"bad schema", "//some.example", nil, true},
		{"bad hostname", "https://", nil, true},
		{"bad parse", "https://^", nil, true},
		{"empty string error", "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAndValidateURL(tt.rawurl)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAndValidateURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("TestParseAndValidateURL() = %s", diff)
			}
		})
	}
}

func TestDeepCopy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		u       *url.URL
		want    *url.URL
		wantErr bool
	}{
		{"nil", nil, nil, false},
		{"good", &url.URL{Scheme: "https", Host: "some.example"}, &url.URL{Scheme: "https", Host: "some.example"}, false},
		{"bad no scheme", &url.URL{Host: "some.example"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeepCopy(tt.u)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeepCopy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DeepCopy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		u       *url.URL
		wantErr bool
	}{
		{"good", &url.URL{Scheme: "https", Host: "some.example"}, false},
		{"nil", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateURL(tt.u); (err != nil) != tt.wantErr {
				t.Errorf("ValidateURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignedRedirectURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		mockedTime  int64
		key         string
		destination *url.URL
		urlToSign   *url.URL
		want        *url.URL
	}{
		{"good", 2, "hunter42", &url.URL{Host: "pomerium.io", Scheme: "https://"}, &url.URL{Host: "pomerium.io", Scheme: "https://", Path: "/ok"}, &url.URL{Host: "pomerium.io", Scheme: "https://", RawQuery: "redirect_uri=https%3A%2F%2F%3A%2F%2Fpomerium.io%2Fok&sig=7jdo1XFcmuhjBHnpfVhll5cXflYByeMnbp5kRz87CVQ%3D&ts=2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testTimeNow = tt.mockedTime
			got := SignedRedirectURL(tt.key, tt.destination, tt.urlToSign)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("SignedRedirectURL() = diff %v", diff)
			}
		})
	}
}

func Test_timestamp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dontWant int64
	}{
		{"if unset should never return", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testTimeNow = tt.dontWant
			if got := timestamp(); got == tt.dontWant {
				t.Errorf("timestamp() = %v, dontWant %v", got, tt.dontWant)
			}
		})
	}
}

func parseURLHelper(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}

func TestGetAbsoluteURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		u    *url.URL
		want *url.URL
	}{
		{"add https", parseURLHelper("http://pomerium.io"), parseURLHelper("https://pomerium.io")},
		{"missing scheme", parseURLHelper("https://pomerium.io"), parseURLHelper("https://pomerium.io")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := http.Request{URL: tt.u, Host: tt.u.Host}
			got := GetAbsoluteURL(&r)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("GetAbsoluteURL() = %v", diff)
			}
		})
	}
}
