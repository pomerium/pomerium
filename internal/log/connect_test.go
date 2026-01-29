package log_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/config/configconnect"
)

func TestConnectInterceptor(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()

	var buf bytes.Buffer
	l := zerolog.New(&buf)
	i := log.ConnectInterceptor(&l)
	mux.Handle(configconnect.NewConfigServiceHandler(&configconnect.UnimplementedConfigServiceHandler{}, connect.WithInterceptors(i)))

	srv := httptest.NewServer(mux)

	client := configconnect.NewConfigServiceClient(http.DefaultClient, srv.URL)
	_, _ = client.ListKeyPairs(t.Context(), connect.NewRequest(&config.ListKeyPairsRequest{}))

	m := map[string]any{}
	assert.NoError(t, json.Unmarshal(buf.Bytes(), &m))
	assert.Equal(t, "debug", m["level"])
	assert.Equal(t, "unimplemented", m["connect.code"])
	assert.Equal(t, "pomerium.config.ConfigService", m["connect.service"])
	assert.Equal(t, "ListKeyPairs", m["connect.method"])
}
