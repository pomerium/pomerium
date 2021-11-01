package requestid

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromContext(t *testing.T) {
	id := New()
	ctx := WithValue(context.Background(), id)
	ctxID := FromContext(ctx)
	assert.Equal(t, ctxID, id)
}
