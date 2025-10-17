package sessions

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/go-cmp/cmp"
)

func TestHandle_UnmarshalJSON(t *testing.T) {
	fixedTime := time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	timeNow = func() time.Time {
		return fixedTime
	}
	defer func() { timeNow = time.Now }()
	tests := []struct {
		name    string
		in      *Handle
		want    *Handle
		wantErr bool
	}{
		{
			"good",
			&Handle{ID: "xyz"},
			&Handle{ID: "xyz", IssuedAt: jwt.NewNumericDate(fixedTime)},
			false,
		},
		{
			"with user",
			&Handle{ID: "xyz"},
			&Handle{ID: "xyz", IssuedAt: jwt.NewNumericDate(fixedTime)},
			false,
		},
		{
			"without",
			&Handle{ID: "xyz", Subject: "user"},
			&Handle{ID: "xyz", Subject: "user", IssuedAt: jwt.NewNumericDate(fixedTime)},
			false,
		},
		{
			"missing id",
			&Handle{},
			&Handle{IssuedAt: jwt.NewNumericDate(fixedTime)},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatal(err)
			}

			h := NewHandle("")
			h.ID = ""
			if err := h.UnmarshalJSON(data); (err != nil) != tt.wantErr {
				t.Errorf("State.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, h); diff != "" {
				t.Errorf("State.UnmarshalJSON() error = %v", diff)
			}
		})
	}
}
