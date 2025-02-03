package envoyconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

func Test_buildLocalReplyConfig(t *testing.T) {
	b := Builder{}
	opts := config.NewDefaultOptions()
	opts.BrandingOptions = &configpb.Settings{
		LogoUrl:                    proto.String("http://example.com/my%20branding%20logo.png"),
		ErrorMessageFirstParagraph: proto.String("It's 100% broken."),
	}
	lrc, err := b.buildLocalReplyConfig(opts)
	require.NoError(t, err)
	tmpl := string(lrc.Mappers[0].GetBodyFormatOverride().GetTextFormatSource().GetInlineBytes())
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
