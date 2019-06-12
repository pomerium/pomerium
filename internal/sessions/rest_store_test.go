package sessions

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/cryptutil"
)

func TestRestStore_SaveSession(t *testing.T) {
	now := time.Date(2008, 1, 8, 17, 5, 05, 0, time.UTC)

	tests := []struct {
		name             string
		optionsName      string
		optionsCipher    cryptutil.Cipher
		sessionState     *SessionState
		wantErr          bool
		wantSaveResponse string
	}{
		{"good", "Authenticate", &cryptutil.MockCipher{MarshalResponse: "test"}, &SessionState{RefreshDeadline: now}, false, `{"Token":"test","Expiry":"2008-01-08T17:05:05Z"}`},
		{"bad session marshal", "Authenticate", &cryptutil.MockCipher{MarshalError: errors.New("error")}, &SessionState{RefreshDeadline: now}, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewRestStore(
				&RestStoreOptions{
					Name:   tt.optionsName,
					Cipher: tt.optionsCipher,
				})
			if err != nil {
				t.Fatalf("NewRestStore err %v", err)
			}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			if err := s.SaveSession(w, r, tt.sessionState); (err != nil) != tt.wantErr {
				t.Errorf("RestStore.SaveSession() error = %v, wantErr %v", err, tt.wantErr)
			}
			resp := w.Result()
			body, _ := ioutil.ReadAll(resp.Body)
			if diff := cmp.Diff(string(body), tt.wantSaveResponse); diff != "" {
				t.Errorf("RestStore.SaveSession() got / want diff \n%s\n", diff)
			}
		})
	}
}

func TestNewRestStore(t *testing.T) {

	tests := []struct {
		name          string
		optionsName   string
		optionsCipher cryptutil.Cipher
		wantErr       bool
	}{
		{"good", "Authenticate", &cryptutil.MockCipher{}, false},
		{"good default to authenticate", "", &cryptutil.MockCipher{}, false},
		{"empty cipher", "Authenticate", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRestStore(
				&RestStoreOptions{
					Name:   tt.optionsName,
					Cipher: tt.optionsCipher,
				})
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRestStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRestStore_ClearSession(t *testing.T) {
	tests := []struct {
		name           string
		expectedStatus int
	}{
		{"always returns reset!", http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &RestStore{Name: "Authenticate", Cipher: &cryptutil.MockCipher{}}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			s.ClearSession(w, r)
			resp := w.Result()
			if diff := cmp.Diff(resp.StatusCode, tt.expectedStatus); diff != "" {
				t.Errorf("RestStore.ClearSession() got / want diff \n%s\n", diff)
			}

		})
	}
}

func TestRestStore_LoadSession(t *testing.T) {

	tests := []struct {
		name          string
		optionsName   string
		optionsCipher cryptutil.Cipher
		token         string
		wantErr       bool
	}{
		{"good", "Authorization", &cryptutil.MockCipher{}, "test", false},
		{"empty auth header", "", &cryptutil.MockCipher{}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &RestStore{
				Name:   tt.optionsName,
				Cipher: tt.optionsCipher,
			}

			r := httptest.NewRequest(http.MethodGet, "/", nil)

			if tt.optionsName != "" {
				r.Header.Set(tt.optionsName, fmt.Sprintf(("Bearer %s"), tt.token))

			}
			_, err := s.LoadSession(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("RestStore.LoadSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
