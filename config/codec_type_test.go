package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

func TestOptions_GetCodecType(t *testing.T) {
	options := NewDefaultOptions()
	assert.Equal(t, configpb.CodecType_CODEC_TYPE_AUTO, options.GetCodecType())
}
