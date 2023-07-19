package autocert

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestCertMagicLogger(t *testing.T) {
	t.Parallel()

	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	var buf bytes.Buffer
	core := zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.DebugLevel)
	core = certMagicLoggerCore{core: core}

	logger := zap.New(core)

	logger.Info("TEST", zap.Error(errors.New("no OCSP server specified in certificate")))
	assert.Empty(t, buf.Bytes())

	logger.Info("TEST")
	assert.NotEmpty(t, buf.Bytes())
}
