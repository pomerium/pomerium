package mock

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestStore(t *testing.T) {
	tests := []struct {
		name        string
		store       *Store
		wantLoad    string
		saveSession *session.Handle
		wantLoadErr bool
		wantSaveErr bool
	}{
		{
			"basic",
			&Store{
				ResponseSession: "test",
				SessionHandle:   &session.Handle{UserId: "0101"},
				Secret:          []byte("01234567890123456789012345678901"),
				SaveError:       nil,
				LoadError:       nil,
			},
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMTAxIn0.H1n3we124lYP3nvZemvLZOCCZYGizGxZ09qwoUTL358",
			&session.Handle{UserId: "0101"},
			false,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := tt.store

			err := ms.WriteSessionHandle(nil, tt.saveSession)
			if (err != nil) != tt.wantSaveErr {
				t.Errorf("mockstore.SaveSession() error = %v, wantSaveErr %v", err, tt.wantSaveErr)
				return
			}
			got, err := ms.ReadSessionHandleJWT(nil)
			if (err != nil) != tt.wantLoadErr {
				t.Errorf("mockstore.LoadSession() error = %v, wantLoadErr %v", err, tt.wantLoadErr)
				return
			}
			assert.Equal(t, tt.wantLoad, string(got))
			ms.ClearSessionHandle(nil)
			if ms.ResponseSession != "" {
				t.Errorf("ResponseSession not empty! %s", ms.ResponseSession)
			}
		})
	}
}
