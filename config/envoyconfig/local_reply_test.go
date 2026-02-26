package envoyconfig_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/interop"
	"google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

func Test_BuildLocalReplyConfig(t *testing.T) {
	t.Parallel()

	b := envoyconfig.Builder{}
	opts := config.NewDefaultOptions()
	opts.BrandingOptions = &configpb.Settings{
		LogoUrl:                    proto.String("http://example.com/my%20branding%20logo.png"),
		ErrorMessageFirstParagraph: proto.String("It's 100% broken."),
	}
	lrc, err := b.BuildLocalReplyConfig(opts)
	require.NoError(t, err)
	tmpl := string(lrc.Mappers[0].GetBodyFormatOverride().GetTextFormatSource().GetInlineBytes())
	assert.Equal(t, `{
  "requestId": "%STREAM_ID%",
  "status": "%RESPONSE_CODE%",
  "statusText": "%RESPONSE_CODE_DETAILS%"
}`, tmpl)
	tmpl = string(lrc.Mappers[1].GetBodyFormatOverride().GetTextFormatSource().GetInlineBytes())
	assert.Equal(t, `{
  "requestId": "%STREAM_ID%",
  "status": "%RESPONSE_CODE%",
  "statusText": "%RESPONSE_CODE_DETAILS%"
}`, tmpl)
	tmpl = string(lrc.Mappers[len(lrc.Mappers)-1].GetBodyFormatOverride().GetTextFormatSource().GetInlineBytes())
	assert.Equal(t, `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <link id="favicon" rel="shortcut icon" href="/.pomerium/favicon.ico?v=2" />
    <link
      class="pomerium_favicon"
      rel="apple-touch-icon"
      sizes="180x180"
      href="/.pomerium/apple-touch-icon.png"
    />
    <link
      class="pomerium_favicon"
      rel="icon"
      sizes="32x32"
      href="/.pomerium/favicon-32x32.png"
    />
    <link
      class="pomerium_favicon"
      rel="icon"
      sizes="16x16"
      href="/.pomerium/favicon-16x16.png"
    />
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1, shrink-to-fit=no"
    />
    <title>Error</title>
    <link rel="stylesheet" href="/.pomerium/index.css" />
  </head>
  <body>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <div id="root"></div>
    <script>
      window.POMERIUM_DATA = {"errorMessageFirstParagraph":"It's 100%% broken.","logoUrl":"http://example.com/my%%20branding%%20logo.png","page":"Error","requestId":"%STREAM_ID%","responseFlags":"%RESPONSE_FLAGS%","status":"%RESPONSE_CODE%","statusText":"%RESPONSE_CODE_DETAILS%"};
    </script>
    <script src="/.pomerium/index.js"></script>
  </body>
</html>
`, tmpl)
}

func TestLocalReply(t *testing.T) {
	t.Parallel()
	env := testenv.New(t)

	httpUpstream := upstreams.HTTP(nil)
	httpRoute := httpUpstream.Route().From(env.SubdomainURL("http1")).Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true })
	env.AddUpstream(httpUpstream)

	grpcUpstream := upstreams.GRPC(insecure.NewCredentials())
	grpc_testing.RegisterTestServiceServer(grpcUpstream, interop.NewTestServer())
	grpcRoute := grpcUpstream.Route().
		From(env.SubdomainURL("grpc1")).
		Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true })

	env.AddUpstream(grpcUpstream)
	env.Start()
	snippets.WaitStartupComplete(env)

	t.Run("grpc", func(t *testing.T) {
		// connect to an invalid from URL so that we get a 404 error
		cc, err := grpc.NewClient(strings.TrimPrefix(strings.Replace(grpcRoute.URL().Value(), "grpc1", "grpc2", -1), "https://"),
			grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(env.ServerCAs(), "")))
		require.NoError(t, err)
		t.Cleanup(func() { _ = cc.Close() })

		client := grpc_testing.NewTestServiceClient(cc)
		_, err = client.EmptyCall(env.Context(), &grpc_testing.Empty{})
		s, ok := status.FromError(err)
		if assert.True(t, ok) {
			assert.Equal(t, codes.NotFound, s.Code())

			var details struct {
				RequestID  string `json:"requestId"`
				Status     string `json:"status"`
				StatusText string `json:"statusText"`
			}
			err = json.Unmarshal([]byte(s.Message()), &details)
			assert.NoError(t, err)
			assert.Equal(t, "404", details.Status)
			assert.Equal(t, "route_not_found", details.StatusText)
		}
	})
	t.Run("http", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, strings.Replace(httpRoute.URL().Value(), "http1", "http2", -1), nil)
		require.NoError(t, err)

		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, res.StatusCode)

		bs, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.Contains(t, string(bs), "<!DOCTYPE html>")
	})
	t.Run("json", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, strings.Replace(httpRoute.URL().Value(), "http1", "http2", -1), nil)
		require.NoError(t, err)
		req.Header.Set("Accept", "application/json")

		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, res.StatusCode)

		bs, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		var details struct {
			RequestID  string `json:"requestId"`
			Status     string `json:"status"`
			StatusText string `json:"statusText"`
		}
		err = json.Unmarshal(bs, &details)
		assert.NoError(t, err)
		assert.Equal(t, "404", details.Status)
		assert.Equal(t, "route_not_found", details.StatusText)
	})
}
