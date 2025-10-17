package queryparam

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/sessions"
)

func TestNewQueryParamStore(t *testing.T) {
	tests := []struct {
		name  string
		State *sessions.Handle

		enc     encoding.MarshalUnmarshaler
		qp      string
		wantErr bool
		wantURL *url.URL
	}{
		{"simple good", &sessions.Handle{}, mock.Encoder{MarshalResponse: []byte("ok")}, "", false, &url.URL{Path: "/", RawQuery: "pomerium_session=ok"}},
		{"marshall error", &sessions.Handle{}, mock.Encoder{MarshalError: errors.New("error")}, "", true, &url.URL{Path: "/"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewStore(tt.enc, tt.qp)

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()

			if err := got.SaveSession(w, r, tt.State); (err != nil) != tt.wantErr {
				t.Errorf("NewStore.SaveSession() error = %v, wantErr %v", err, tt.wantErr)
			}

			if diff := cmp.Diff(r.URL, tt.wantURL); diff != "" {
				t.Errorf("NewStore() = %v", diff)
			}
			got.ClearSession(w, r)
			if diff := cmp.Diff(r.URL, &url.URL{Path: "/"}); diff != "" {
				t.Errorf("NewStore() = %v", diff)
			}
		})
	}
}
