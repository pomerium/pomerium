package authenticator

import (
	"net/url"
	"reflect"
	"testing"
)

func TestNew(t *testing.T) {
	type args struct {
		uri                    *url.URL
		internalURL            string
		OverideCertificateName string
		key                    string
	}
	tests := []struct {
		name    string
		args    args
		wantP   Authenticator
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotP, err := New(tt.args.uri, tt.args.internalURL, tt.args.OverideCertificateName, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotP, tt.wantP) {
				t.Errorf("New() = %v, want %v", gotP, tt.wantP)
			}
		})
	}
}
