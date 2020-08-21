package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/integration/internal/flows"
)

func TestForwardAuth(t *testing.T) {
	ctx := mainCtx
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	client := testcluster.NewHTTPClient()
	res, err := flows.Authenticate(ctx, client, mustParseURL("https://fa-httpdetails.localhost.pomerium.io/by-user"),
		flows.WithForwardAuth(true), flows.WithEmail("bob@dogs.test"), flows.WithGroups("user"))
	if !assert.NoError(t, err, "unexpected http error") {
		return
	}
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
}
