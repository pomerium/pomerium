package frontend

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTemplates(t *testing.T) {
	tpl, err := NewTemplates()
	require.NoError(t, err)

	var buf bytes.Buffer
	err = tpl.ExecuteTemplate(&buf, "header.html", nil)
	require.NoError(t, err)

	assert.Contains(t, buf.String(), `<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />`)
}
