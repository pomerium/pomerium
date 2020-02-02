package mock // import "github.com/pomerium/pomerium/internal/sessions/mock"

import (
	"reflect"
	"testing"

	"github.com/pomerium/pomerium/internal/sessions"
)

func TestStore(t *testing.T) {
	tests := []struct {
		name        string
		mockCSRF    *Store
		saveSession *sessions.State
		wantLoadErr bool
		wantSaveErr bool
	}{
		{"basic",
			&Store{
				ResponseSession: "test",
				Session:         &sessions.State{Subject: "0101"},
				SaveError:       nil,
				LoadError:       nil,
			},
			&sessions.State{Subject: "0101"},
			false,
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := tt.mockCSRF

			err := ms.SaveSession(nil, nil, tt.saveSession)
			if (err != nil) != tt.wantSaveErr {
				t.Errorf("MockCSRFStore.GetCSRF() error = %v, wantSaveErr %v", err, tt.wantSaveErr)
				return
			}
			got, _, err := ms.LoadSession(nil)
			if (err != nil) != tt.wantLoadErr {
				t.Errorf("MockCSRFStore.GetCSRF() error = %v, wantLoadErr %v", err, tt.wantLoadErr)
				return
			}
			if !reflect.DeepEqual(got, tt.mockCSRF.Session) {
				t.Errorf("MockCSRFStore.GetCSRF() = %v, want %v", got, tt.mockCSRF.Session)
			}
			ms.ClearSession(nil, nil)
			if ms.ResponseSession != "" {
				t.Errorf("ResponseSession not empty! %s", ms.ResponseSession)
			}
		})
	}
}
