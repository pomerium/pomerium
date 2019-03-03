package authorize

import (
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"testing"
)

func TestOptionsFromEnvConfig(t *testing.T) {
	t.Parallel()
	os.Clearenv()
	tests := []struct {
		name     string
		want     *Options
		envKey   string
		envValue string
		wantErr  bool
	}{
		{"shared secret missing", nil, "", "", true},
		{"with secret", &Options{SharedKey: "aGkK"}, "SHARED_SECRET", "aGkK", false},
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

func TestNew(t *testing.T) {
	t.Parallel()
	content := []byte(`[{"from": "pomerium.io","to":"httpbin.org"}]`)
	tmpfile, err := ioutil.TempFile("", "example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write(content); err != nil {
		log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}
	tests := []struct {
		name       string
		SharedKey  string
		Policy     string
		PolicyFile string
		wantErr    bool
	}{
		{"good", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", "WwogIHsKICAgICJyb3V0ZXMiOiAiaHR0cDovL3BvbWVyaXVtLmlvIgogIH0KXQ==", "", false},
		{"bad shared secret", "AZA85podM73CjLCjViDNz1EUvvejKpWp7Hysr0knXA==", "WwogIHsKICAgICJyb3V0ZXMiOiAiaHR0cDovL3BvbWVyaXVtLmlvIgogIH0KXQ==", "", true},
		{"really bad shared secret", "sup", "WwogIHsKICAgICJyb3V0ZXMiOiAiaHR0cDovL3BvbWVyaXVtLmlvIgogIH0KXQ==", "", true},
		{"bad base64 policy", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", "WwogIHsKICAgICJyb3V0ZXMiOiAiaHR0cDovL3BvbWVyaXVtLmlvIgogIH0KXQ^=", "", true},
		{"bad json", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", "e30=", "", true},
		{"no policies", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", "", "", true},
		{"good policy file", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", "", "./testdata/basic.json", true},
		{"bad policy file, directory", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", "", "./testdata/", true},
		{"good policy", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", "WwogIHsKICAgICJyb3V0ZXMiOiAiaHR0cDovL3BvbWVyaXVtLmlvIgogIH0KXQ==", "", false},
		{"good file", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", "", tmpfile.Name(), false},
		{"validation error, short secret", "AZA85podM73CjLCjViDNz1EUvvejKpWp7Hysr0knXA==", "", "", true},
		{"nil options", "", "", "", true}, // special case
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{SharedKey: tt.SharedKey, Policy: tt.Policy, PolicyFile: tt.PolicyFile}
			if tt.name == "nil options" {
				o = nil
			}
			_, err := New(o)
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
