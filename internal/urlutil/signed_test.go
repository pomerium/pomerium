package urlutil

import (
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestSignedURL(t *testing.T) {
	original := time.Unix(1574117851, 0) // ;-)
	tests := []struct {
		name     string
		key      string
		uri      url.URL
		origTime func() time.Time
		newTime  func() time.Time
		wantStr  string
		want     url.URL
		wantErr  bool
	}{
		{"good", "test-key", url.URL{Scheme: "https", Host: "pomerium.io"},
			func() time.Time { return original }, func() time.Time { return original },
			"https://pomerium.io?pomerium_expiry=1574118151&pomerium_issued=1574117851&pomerium_signature=KIdaRlvAl3XHt6-6w-3aaoWQHXxBzui5BcRYWBmovoM%3D",
			url.URL{Scheme: "https", Host: "pomerium.io", RawQuery: "pomerium_expiry=1574118151&pomerium_issued=1574117851&pomerium_signature=KIdaRlvAl3XHt6-6w-3aaoWQHXxBzui5BcRYWBmovoM%3D"},
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signedURL := NewSignedURL(tt.key, &tt.uri)
			signedURL.timeNow = tt.origTime

			if diff := cmp.Diff(signedURL.String(), tt.wantStr); diff != "" {
				t.Errorf("signedURL() = %v", diff)
			}

			signedURL = NewSignedURL(tt.key, &tt.uri)
			signedURL.timeNow = tt.origTime
			got := signedURL.Sign()

			if diff := cmp.Diff(*got, tt.want); diff != "" {
				t.Errorf("NewSignedURL() = %s", diff)
			}
			err := signedURL.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}

			u, err := url.Parse(signedURL.String())
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(u, got); diff != "" {
				t.Errorf("signedURL() = %v", diff)
			}
			// subsequent string calls shouldn't result in a change
			u, err = url.Parse(signedURL.String())
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(u, got); diff != "" {
				t.Errorf("signedURL() = %v", diff)
			}
		})
	}
}

func TestSignedURL_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		uri     url.URL
		key     string
		timeNow func() time.Time

		wantErr bool
	}{
		{"good", url.URL{Scheme: "https", Host: "pomerium.io", RawQuery: "pomerium_expiry=1574118151&pomerium_issued=1574117851&pomerium_signature=KIdaRlvAl3XHt6-6w-3aaoWQHXxBzui5BcRYWBmovoM%3D"}, "test-key", func() time.Time { return time.Unix(1574117851, 0) }, false},
		{"bad key", url.URL{Scheme: "https", Host: "pomerium.io", RawQuery: "pomerium_expiry=1574118151&pomerium_issued=1574117851&pomerium_signature=KIdaRlvAl3XHt6-6w-3aaoWQHXxBzui5BcRYWBmovoM%3D"}, "bad-key", func() time.Time { return time.Unix(1574117851, 0) }, true},
		{"bad no expiry", url.URL{Scheme: "https", Host: "pomerium.io", RawQuery: "pomerium_issued=1574117851&pomerium_signature=KIdaRlvAl3XHt6-6w-3aaoWQHXxBzui5BcRYWBmovoM%3D"}, "test-key", func() time.Time { return time.Unix(1574117851, 0) }, true},
		{"bad issued", url.URL{Scheme: "https", Host: "pomerium.io", RawQuery: "pomerium_expiry=1574118151&pomerium_signature=KIdaRlvAl3XHt6-6w-3aaoWQHXxBzui5BcRYWBmovoM%3D"}, "test-key", func() time.Time { return time.Unix(1574117851, 0) }, true},
		{"bad signature body", url.URL{Scheme: "https", Host: "pomerium.io", RawQuery: "pomerium_expiry=1574118151&pomerium_issued=1574117851&pomerium_signature=^"}, "test-key", func() time.Time { return time.Unix(1574117851, 0) }, true},
		{"bad expired", url.URL{Scheme: "https", Host: "pomerium.io", RawQuery: "pomerium_expiry=1574118151&pomerium_issued=1574117851&pomerium_signature=KIdaRlvAl3XHt6-6w-3aaoWQHXxBzui5BcRYWBmovoM%3D"}, "test-key", func() time.Time { return time.Unix(1574117851, 0).Add(time.Hour) }, true},
		{"bad not yet valid", url.URL{Scheme: "https", Host: "pomerium.io", RawQuery: "pomerium_expiry=1574118151&pomerium_issued=1574117851&pomerium_signature=KIdaRlvAl3XHt6-6w-3aaoWQHXxBzui5BcRYWBmovoM%3D"}, "test-key", func() time.Time { return time.Unix(1574117851, 0).Add(-time.Hour) }, true},
		{"good scheme doesn't matter", url.URL{Scheme: "http", Host: "pomerium.io", RawQuery: "pomerium_expiry=1574118151&pomerium_issued=1574117851&pomerium_signature=KIdaRlvAl3XHt6-6w-3aaoWQHXxBzui5BcRYWBmovoM%3D"}, "test-key", func() time.Time { return time.Unix(1574117851, 0) }, false},
		{"good scheme doesn't matter", url.URL{Scheme: "//", Host: "pomerium.io", RawQuery: "pomerium_expiry=1574118151&pomerium_issued=1574117851&pomerium_signature=KIdaRlvAl3XHt6-6w-3aaoWQHXxBzui5BcRYWBmovoM%3D"}, "test-key", func() time.Time { return time.Unix(1574117851, 0) }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := NewSignedURL(tt.key, &tt.uri)
			out.timeNow = tt.timeNow

			if err := out.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("SignedURL.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
