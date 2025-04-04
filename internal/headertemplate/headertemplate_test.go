package headertemplate_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/headertemplate"
)

func TestRender(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in     string
		expect string
	}{
		{"x $$ y $$ z", "x $ y $ z"},
		{`${x.y.z}`, `<x,y,z>`},
		{`${   x   .	y .  z }`, `<x,y,z>`},
		{`${x["y"].z}`, `<x,y,z>`},
		{`${x["`, `${x["`},
		{`${`, `${`},
		{`${}`, `${}`},
		{`${x["\\"]}`, `<x,\>`},
		{`${x["\""]}`, `<x,">`},

		{`${pomerium.access_token}`, `<pomerium,access_token>`},
		{`$pomerium.access_token`, `<pomerium,access_token>`},
		{`${pomerium.client_cert_fingerprint}`, `<pomerium,client_cert_fingerprint>`},
		{`$pomerium.client_cert_fingerprint`, `<pomerium,client_cert_fingerprint>`},
		{`${pomerium.id_token}`, `<pomerium,id_token>`},
		{`$pomerium.id_token`, `<pomerium,id_token>`},
		{`${pomerium.jwt}`, `<pomerium,jwt>`},
		{`$pomerium.jwt`, `<pomerium,jwt>`},
		{`${pomerium.request.headers["X-Access-Token"]}`, `<pomerium,request,headers,X-Access-Token>`},
		{`$pomerium.request.headers.X-Access-Token`, `<pomerium,request,headers,X-Access-Token>`},
	} {
		actual := headertemplate.Render(tc.in, func(ref []string) string {
			return "<" + strings.Join(ref, ",") + ">"
		})
		assert.Equal(t, tc.expect, actual)
	}

	assert.Equal(t, "x $ y $ z", headertemplate.Render("x $$ y $$ z", func(_ []string) string {
		return ""
	}))
	assert.Equal(t, "before JWT after", headertemplate.Render("before $pomerium.jwt after", func(ref []string) string {
		assert.Equal(t, []string{"pomerium", "jwt"}, ref)
		return "JWT"
	}))
	assert.Equal(t, "before JWT after", headertemplate.Render("before ${   pomerium  .  jwt  } after", func(ref []string) string {
		assert.Equal(t, []string{"pomerium", "jwt"}, ref)
		return "JWT"
	}))
	assert.Equal(t, "before JWT after", headertemplate.Render("before ${   pomerium  .  jwt  } after", func(ref []string) string {
		assert.Equal(t, []string{"pomerium", "jwt"}, ref)
		return "JWT"
	}))
}
