package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptions_GetCodecType(t *testing.T) {
	options := NewDefaultOptions()
	assert.Equal(t, CodecTypeHTTP1, options.GetCodecType())
	options.Services = "proxy"
	assert.Equal(t, CodecTypeAuto, options.GetCodecType())
	options.Services = "all"
	options.CodecType = CodecTypeAuto
	assert.Equal(t, CodecTypeAuto, options.GetCodecType())
}
