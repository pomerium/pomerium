package frontend

import (
	"html/template"
	"reflect"
	"testing"

	_ "github.com/pomerium/pomerium/internal/frontend/statik"
	"github.com/rakyll/statik/fs"
)

func TestTemplatesCompile(t *testing.T) {
	templates := template.Must(NewTemplates())
	if templates == nil {
		t.Errorf("unexpected nil value %#v", templates)
	}
}

func TestNewTemplates(t *testing.T) {
	tests := []struct {
		name     string
		testData string
		want     *template.Template
		wantErr  bool
	}{
		{"empty statik fs", "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs.Register(tt.testData)
			got, err := NewTemplates()
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTemplates() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTemplates() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMustAssetHandler(t *testing.T) {
	tests := []struct {
		name      string
		testData  string
		wantPanic bool
	}{
		{"empty statik fs", "", true},
		{"empty statik fs", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("The code did not panic")
				}
			}()
			MustAssetHandler()

		})
	}
}
