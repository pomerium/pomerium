package policy

import (
	"net/url"
	"reflect"
	"testing"
)

func TestFromConfig(t *testing.T) {
	t.Parallel()
	source, _ := urlParse("pomerium.io")
	dest, _ := urlParse("httpbin.org")

	tests := []struct {
		name      string
		yamlBytes []byte
		want      []Policy
		wantErr   bool
	}{
		{"simple json", []byte(`[{"from": "pomerium.io","to":"httpbin.org"}]`), []Policy{{From: "pomerium.io", To: "httpbin.org", Source: source, Destination: dest}}, false},
		{"bad from", []byte(`[{"from": "%","to":"httpbin.org"}]`), nil, true},
		{"bad to", []byte(`[{"from": "pomerium.io","to":"%"}]`), nil, true},
		{"simple error", []byte(`{}`), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromConfig(tt.yamlBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromConfig() = \n%v, want \n%v", got, tt.want)
			}
		})
	}
}

func Test_urlParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		uri     string
		want    *url.URL
		wantErr bool
	}{
		{"good url without schema", "accounts.google.com", &url.URL{Scheme: "https", Host: "accounts.google.com"}, false},
		{"good url with schema", "https://accounts.google.com", &url.URL{Scheme: "https", Host: "accounts.google.com"}, false},
		{"bad url, malformed", "https://accounts.google.^", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := urlParse(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("urlParse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("urlParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFromConfigFile(t *testing.T) {
	t.Parallel()
	source, _ := urlParse("pomerium.io")
	dest, _ := urlParse("httpbin.org")

	tests := []struct {
		name    string
		f       string
		want    []Policy
		wantErr bool
	}{
		{"simple json", "./testdata/basic.json", []Policy{{From: "pomerium.io", To: "httpbin.org", Source: source, Destination: dest}}, false},
		{"simple yaml", "./testdata/basic.yaml", []Policy{{From: "pomerium.io", To: "httpbin.org", Source: source, Destination: dest}}, false},
		{"failed dir", "./testdata/", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromConfigFile(tt.f)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromConfigFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromConfigFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
