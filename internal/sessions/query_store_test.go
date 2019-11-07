package sessions

import (
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/mock"
)

func TestNewQueryParamStore(t *testing.T) {

	tests := []struct {
		name  string
		State *State

		enc     encoding.MarshalUnmarshaler
		qp      string
		wantErr bool
		wantURL *url.URL
	}{
		{"simple good", &State{Email: "user@domain.com", User: "user"}, mock.Encoder{MarshalResponse: []byte("ok")}, "", false, &url.URL{Path: "/", RawQuery: "pomerium_session=ok"}},
		{"marshall error", &State{Email: "user@domain.com", User: "user"}, mock.Encoder{MarshalError: errors.New("error")}, "", true, &url.URL{Path: "/"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewQueryParamStore(tt.enc, tt.qp)

			r := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()

			if err := got.SaveSession(w, r, tt.State); (err != nil) != tt.wantErr {
				t.Errorf("NewQueryParamStore.SaveSession() error = %v, wantErr %v", err, tt.wantErr)
			}

			if diff := cmp.Diff(r.URL, tt.wantURL); diff != "" {
				t.Errorf("NewQueryParamStore() = %v", diff)
			}
			got.ClearSession(w, r)
			if diff := cmp.Diff(r.URL, &url.URL{Path: "/"}); diff != "" {
				t.Errorf("NewQueryParamStore() = %v", diff)
			}
		})
	}
}
