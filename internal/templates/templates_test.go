package templates // import "github.com/pomerium/pomerium/internal/templates"

import (
	"testing"
)

func TestTemplatesCompile(t *testing.T) {
	templates := New()
	if templates == nil {
		t.Errorf("unexpected nil value %#v", templates)

	}
}
