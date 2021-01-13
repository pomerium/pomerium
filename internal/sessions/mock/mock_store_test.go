package mock

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/pomerium/pomerium/internal/sessions"
)

func TestStore(t *testing.T) {
	tests := []struct {
		name        string
		store       *Store
		wantLoad    string
		saveSession *sessions.State
		wantLoadErr bool
		wantSaveErr bool
	}{
		{
			"basic",
			&Store{
				ResponseSession: "test",
				Session:         &sessions.State{Subject: "0101"},
				SaveError:       nil,
				LoadError:       nil,
			},
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwcm9ncmFtbWF0aWMiOmZhbHNlLCJzdWIiOiIwMTAxIn0.PXmONj-P1lV2BVAZ21lTicAapZr3wKdQhNxNHoYzvM",
			&sessions.State{Subject: "0101"},
			false,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := tt.store

			err := ms.SaveSession(nil, nil, tt.saveSession)
			if (err != nil) != tt.wantSaveErr {
				t.Errorf("mockstore.SaveSession() error = %v, wantSaveErr %v", err, tt.wantSaveErr)
				return
			}
			got, err := ms.LoadSession(nil)
			if (err != nil) != tt.wantLoadErr {
				t.Errorf("mockstore.LoadSession() error = %v, wantLoadErr %v", err, tt.wantLoadErr)
				return
			}
			if diff := cmp.Diff(got, tt.wantLoad); diff != "" {
				t.Errorf("mockstore.LoadSession() = %v", diff)
			}
			ms.ClearSession(nil, nil)
			if ms.ResponseSession != "" {
				t.Errorf("ResponseSession not empty! %s", ms.ResponseSession)
			}
		})
	}
}
