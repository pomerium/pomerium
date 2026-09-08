package authorize

import (
	"net/http"
	"net/http/httptest"
	"testing"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	hpke_handlers "github.com/pomerium/pomerium/pkg/hpke/handlers"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

func newTestAuthorize(t *testing.T) *Authorize {
	t.Helper()
	opt := config.NewDefaultOptions()
	opt.DataBroker.ServiceURL = "https://databroker.example.com"
	opt.SharedKey = "E8wWIMnihUx+AUfRegAQDNs8eRb3UrB5G3zlJW9XJDM="

	hpkePrivateKey, err := opt.GetHPKEPrivateKey()
	require.NoError(t, err)
	authnSrv := httptest.NewServer(hpke_handlers.HPKEPublicKeyHandler(hpkePrivateKey.PublicKey()))
	t.Cleanup(authnSrv.Close)
	opt.AuthenticateURLString = authnSrv.URL

	a, err := New(t.Context(), config.New(opt))
	require.NoError(t, err)
	return a
}

func TestHandleResultSecretUnavailable(t *testing.T) {
	t.Parallel()
	a := newTestAuthorize(t)

	t.Run("allowed but secret unavailable => 503", func(t *testing.T) {
		res, err := a.handleResult(t.Context(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{Policy: &config.Policy{From: "https://app.example.com"}},
			&evaluator.Result{
				Allow:              evaluator.NewRuleResult(true, criteria.ReasonPomeriumRoute),
				SecretsUnavailable: &evaluator.SecretsUnavailableError{BindingID: "tok", HeaderName: "Authorization"},
			})
		require.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, int(res.GetDeniedResponse().GetStatus().GetCode()))
	})

	t.Run("policy deny takes precedence over secret unavailable", func(t *testing.T) {
		res, err := a.handleResult(t.Context(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{Policy: &config.Policy{From: "https://app.example.com"}},
			&evaluator.Result{
				Allow:              evaluator.NewRuleResult(false),
				Deny:               evaluator.NewRuleResult(true, criteria.ReasonRouteNotFound),
				SecretsUnavailable: &evaluator.SecretsUnavailableError{BindingID: "tok", HeaderName: "Authorization"},
			})
		require.NoError(t, err)
		assert.NotEqual(t, http.StatusServiceUnavailable, int(res.GetDeniedResponse().GetStatus().GetCode()),
			"policy deny must win, not the secret 503")
	})

	t.Run("allowed with no marker => ok", func(t *testing.T) {
		res, err := a.handleResult(t.Context(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{Policy: &config.Policy{From: "https://app.example.com"}},
			&evaluator.Result{
				Allow: evaluator.NewRuleResult(true, criteria.ReasonPomeriumRoute),
			})
		require.NoError(t, err)
		assert.NotNil(t, res.GetOkResponse())
	})
}
