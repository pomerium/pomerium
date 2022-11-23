package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptions_GetCodecType(t *testing.T) {
	options := NewDefaultOptions()
	assert.Equal(t, CodecTypeAuto, options.GetCodecType())
}
