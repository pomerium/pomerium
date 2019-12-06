package httputil

import (
	"reflect"
	"testing"

	"github.com/gorilla/mux"
)

func TestNewRouter(t *testing.T) {
	tests := []struct {
		name string
		want *mux.Router
	}{
		{"this is a gorilla router right?", mux.NewRouter()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewRouter(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRouter() = %v, want %v", got, tt.want)
			}
		})
	}
}
