package envoyconfig_test

import (
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/interop"
	"google.golang.org/grpc/interop/grpc_testing"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
)

func TestH2C(t *testing.T) {
	env := testenv.New(t)

	up := upstreams.GRPC(insecure.NewCredentials())
	grpc_testing.RegisterTestServiceServer(up, interop.NewTestServer())

	http := up.Route().
		From(env.SubdomainURL("grpc-http")).
		To(values.Bind(up.Port(), func(port int) string {
			// override the target protocol to use http://
			return fmt.Sprintf("http://127.0.0.1:%d", port)
		})).
		Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true })

	h2c := up.Route().
		From(env.SubdomainURL("grpc-h2c")).
		Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true })

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	t.Run("h2c", func(t *testing.T) {
		t.Parallel()
		recorder := env.NewLogRecorder()

		cc := up.Dial(h2c)
		client := grpc_testing.NewTestServiceClient(cc)
		_, err := client.EmptyCall(env.Context(), &grpc_testing.Empty{})
		require.NoError(t, err)
		cc.Close()

		recorder.Match([]map[string]any{
			{
				"service":               "envoy",
				"path":                  "/grpc.testing.TestService/EmptyCall",
				"message":               "http-request",
				"response-code-details": "via_upstream",
			},
		})
	})
	t.Run("http", func(t *testing.T) {
		t.Parallel()
		recorder := env.NewLogRecorder()

		cc := up.Dial(http)
		client := grpc_testing.NewTestServiceClient(cc)
		_, err := client.UnaryCall(env.Context(), &grpc_testing.SimpleRequest{})
		require.Error(t, err)
		cc.Close()

		recorder.Match([]map[string]any{
			{
				"service":               "envoy",
				"path":                  "/grpc.testing.TestService/UnaryCall",
				"message":               "http-request",
				"response-code-details": "upstream_reset_before_response_started{protocol_error}",
			},
		})
	})
}

func TestHTTP(t *testing.T) {
	env := testenv.New(t)

	up := upstreams.HTTP(nil)
	up.Handle("/foo", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "hello world")
	})

	route := up.Route().
		From(env.SubdomainURL("http")).
		Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true })

	env.AddUpstream(up)
	env.Start()

	recorder := env.NewLogRecorder()

	resp, err := up.Get(route, upstreams.Path("/foo"))
	require.NoError(t, err)

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "hello world\n", string(data))

	recorder.Match([]map[string]any{
		{
			"service":               "envoy",
			"path":                  "/foo",
			"method":                "GET",
			"message":               "http-request",
			"response-code-details": "via_upstream",
		},
	})
}

func TestClientCert(t *testing.T) {
	env := testenv.New(t)
	env.Add(scenarios.DownstreamMTLS(config.MTLSEnforcementRejectConnection))

	up := upstreams.HTTP(nil)
	up.Handle("/foo", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "hello world")
	})

	clientCert := env.NewClientCert()

	route := up.Route().
		From(env.SubdomainURL("http")).
		PPL(fmt.Sprintf(`{"allow":{"and":["client_certificate":{"fingerprint":%q}]}}`, clientCert.Fingerprint()))

	env.AddUpstream(up)
	env.Start()

	recorder := env.NewLogRecorder()

	resp, err := up.Get(route, upstreams.Path("/foo"), upstreams.ClientCert(clientCert))
	require.NoError(t, err)

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "hello world\n", string(data))

	recorder.Match([]map[string]any{
		{
			"service":               "envoy",
			"path":                  "/foo",
			"method":                "GET",
			"message":               "http-request",
			"response-code-details": "via_upstream",
			"client-certificate":    clientCert,
		},
	})
}
