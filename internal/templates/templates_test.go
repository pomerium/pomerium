package templates // import "github.com/pomerium/pomerium/internal/templates"

import (
	"testing"

	"github.com/pomerium/pomerium/internal/testutil"
)

func TestTemplatesCompile(t *testing.T) {
	templates := New()
	testutil.NotEqual(t, templates, nil)
}
