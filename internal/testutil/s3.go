package testutil

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/stretchr/testify/require"
)

func WithTestS3(t *testing.T, handler func(endpoint string)) {
	t.Helper()

	backend := s3mem.New()
	faker := gofakes3.New(backend, gofakes3.WithAutoBucket(true))
	ts := httptest.NewServer(faker.Server())
	t.Cleanup(ts.Close)
	u, err := url.Parse(ts.URL)
	require.NoError(t, err)

	handler("ACCESS_KEY:SECRET_KEY@" + u.Host)
}
