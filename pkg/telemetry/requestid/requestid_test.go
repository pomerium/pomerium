package requestid

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromContext(t *testing.T) {
	id := New()
	ctx := WithValue(t.Context(), id)
	ctxID := FromContext(ctx)
	assert.Equal(t, ctxID, id)
}
