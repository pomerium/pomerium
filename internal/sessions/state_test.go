package sessions

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/go-cmp/cmp"
)

func TestState_UnmarshalJSON(t *testing.T) {
	fixedTime := time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	timeNow = func() time.Time {
		return fixedTime
	}
	defer func() { timeNow = time.Now }()
	expiresAt := fixedTime.Add(time.Minute)
	tests := []struct {
		name    string
		in      *State
		want    *State
		wantErr bool
	}{
		{
			"good",
			&State{ID: "xyz"},
			&State{ID: "xyz", IssuedAt: jwt.NewNumericDate(fixedTime), ExpiresAt: jwt.NewNumericDate(expiresAt)},
			false,
		},
		{
			"with user",
			&State{ID: "xyz"},
			&State{ID: "xyz", IssuedAt: jwt.NewNumericDate(fixedTime), ExpiresAt: jwt.NewNumericDate(expiresAt)},
			false,
		},
		{
			"without",
			&State{ID: "xyz", Subject: "user"},
			&State{ID: "xyz", Subject: "user", IssuedAt: jwt.NewNumericDate(fixedTime), ExpiresAt: jwt.NewNumericDate(expiresAt)},
			false,
		},
		{
			"missing id",
			&State{},
			&State{IssuedAt: jwt.NewNumericDate(fixedTime), ExpiresAt: jwt.NewNumericDate(expiresAt)},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatal(err)
			}

			s := NewState("", time.Minute)
			s.ID = ""
			if err := s.UnmarshalJSON(data); (err != nil) != tt.wantErr {
				t.Errorf("State.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, s); diff != "" {
				t.Errorf("State.UnmarshalJSON() error = %v", diff)
			}
		})
	}
}
