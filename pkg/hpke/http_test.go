package hpke_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/hpke"
	hpke_handlers "github.com/pomerium/pomerium/pkg/hpke/handlers"
)

func TestFetchPublicKeyFromJWKS(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	t.Cleanup(clearTimeout)

	hpkePrivateKey, err := hpke.GeneratePrivateKey()
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hpke_handlers.HPKEPublicKeyHandler(hpkePrivateKey.PublicKey()).ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	publicKey, err := hpke.FetchPublicKey(ctx, http.DefaultClient, srv.URL)
	assert.NoError(t, err)
	assert.Equal(t, hpkePrivateKey.PublicKey().String(), publicKey.String())
}
