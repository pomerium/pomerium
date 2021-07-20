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
		{"path segment", "192.168.0.1:1234/path", nil, true},
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

func TestGetDomainsForURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		u    *url.URL
		want []string
	}{
		{"http", &url.URL{Scheme: "http", Host: "example.com"}, []string{"example.com", "example.com:80"}},
		{"http scheme with host contain 443", &url.URL{Scheme: "http", Host: "example.com:443"}, []string{"example.com:443"}},
		{"https", &url.URL{Scheme: "https", Host: "example.com"}, []string{"example.com", "example.com:443"}},
		{"Host contains other port", &url.URL{Scheme: "https", Host: "example.com:1234"}, []string{"example.com:1234"}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := GetDomainsForURL(*tc.u)
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("GetDomainsForURL() = %v", diff)
			}
		})
	}
}
