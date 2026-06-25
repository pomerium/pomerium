package canonicallinks_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/mcp/configapi/canonicallinks"
)

// asDynamic round-trips msg through dynamicpb so the resulting message has
// the same field-options visibility as configapi's runtime instances.
// MetaContributors must work against *dynamicpb.Message.
func asDynamic(t *testing.T, msg proto.Message) protoreflect.Message {
	t.Helper()
	b, err := proto.Marshal(msg)
	require.NoError(t, err)
	out := dynamicpb.NewMessage(msg.ProtoReflect().Descriptor())
	require.NoError(t, proto.Unmarshal(b, out))
	return out
}

func TestNestedID(t *testing.T) {
	t.Parallel()

	t.Run("returns id when wrapper present", func(t *testing.T) {
		t.Parallel()
		r := asDynamic(t, &configpb.GetRouteResponse{
			Route: &configpb.Route{Id: new("route-1")},
		})
		assert.Equal(t, "route-1", canonicallinks.NestedID(r, "route"))
	})

	t.Run("empty when wrapper unset", func(t *testing.T) {
		t.Parallel()
		r := asDynamic(t, &configpb.GetRouteResponse{})
		assert.Equal(t, "", canonicallinks.NestedID(r, "route"))
	})

	t.Run("empty when wrapper field name unknown", func(t *testing.T) {
		t.Parallel()
		r := asDynamic(t, &configpb.GetRouteResponse{
			Route: &configpb.Route{Id: new("route-1")},
		})
		assert.Equal(t, "", canonicallinks.NestedID(r, "policy"))
	})

	t.Run("empty when wrapper has no id", func(t *testing.T) {
		t.Parallel()
		r := asDynamic(t, &configpb.GetRouteResponse{
			Route: &configpb.Route{},
		})
		assert.Equal(t, "", canonicallinks.NestedID(r, "route"))
	})
}

func TestNestedNamespaceID(t *testing.T) {
	t.Parallel()

	t.Run("returns nested namespace_id", func(t *testing.T) {
		t.Parallel()
		ns := "ns-42"
		r := asDynamic(t, &configpb.GetRouteResponse{
			Route: &configpb.Route{Id: new("r1"), NamespaceId: &ns},
		})
		assert.Equal(t, "ns-42", canonicallinks.NestedNamespaceID(r))
	})

	t.Run("empty when no nested namespace_id", func(t *testing.T) {
		t.Parallel()
		r := asDynamic(t, &configpb.GetRouteResponse{
			Route: &configpb.Route{Id: new("r1")},
		})
		assert.Equal(t, "", canonicallinks.NestedNamespaceID(r))
	})

	t.Run("empty when no nested entity at all", func(t *testing.T) {
		t.Parallel()
		r := asDynamic(t, &configpb.GetRouteResponse{})
		assert.Equal(t, "", canonicallinks.NestedNamespaceID(r))
	})
}

func TestEntityPath(t *testing.T) {
	t.Parallel()

	id := new("r-9")
	ns := "ns-7"

	t.Run("formats path and appends cid", func(t *testing.T) {
		t.Parallel()
		r := asDynamic(t, &configpb.GetRouteResponse{
			Route: &configpb.Route{Id: id, NamespaceId: &ns},
		})
		got, ok := canonicallinks.EntityPath(r, "/app/management/routes/%s/edit", "route")
		assert.True(t, ok)
		assert.Equal(t, "/app/management/routes/r-9/edit?cid=ns-7", got)
	})

	t.Run("omits cid when no namespace_id set", func(t *testing.T) {
		t.Parallel()
		r := asDynamic(t, &configpb.GetRouteResponse{
			Route: &configpb.Route{Id: id},
		})
		got, ok := canonicallinks.EntityPath(r, "/x/%s", "route")
		assert.True(t, ok)
		assert.Equal(t, "/x/r-9", got)
	})

	t.Run("returns ok=false when wrapper has no id", func(t *testing.T) {
		t.Parallel()
		r := asDynamic(t, &configpb.GetRouteResponse{Route: &configpb.Route{}})
		_, ok := canonicallinks.EntityPath(r, "/x/%s", "route")
		assert.False(t, ok)
	})
}

func TestWithClusterScopeQuery(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		cid  string
		want string
	}{
		{"empty cid leaves url alone", "https://x/y", "", "https://x/y"},
		{"adds first param", "https://x/y", "abc", "https://x/y?cid=abc"},
		{"appends to existing query", "https://x/y?foo=bar", "abc", "https://x/y?foo=bar&cid=abc"},
		{"escapes cid value", "https://x/y", "a b/c", "https://x/y?cid=a+b%2Fc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, canonicallinks.WithClusterScopeQuery(tc.in, tc.cid))
		})
	}
}

func TestNewMetaContributor(t *testing.T) {
	t.Parallel()

	t.Run("nil when baseURL empty", func(t *testing.T) {
		t.Parallel()
		got := canonicallinks.NewMetaContributor("", func(protoreflect.Message) (string, bool) {
			return "/x", true
		})
		assert.Nil(t, got)
	})

	t.Run("nil when resolver nil", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, canonicallinks.NewMetaContributor("https://x", nil))
	})

	t.Run("emits links.canonical when resolver matches", func(t *testing.T) {
		t.Parallel()
		ns := "ns-1"
		msg := &configpb.GetRouteResponse{
			Route: &configpb.Route{Id: new("r1"), NamespaceId: &ns},
		}
		c := canonicallinks.NewMetaContributor("https://console.example.com",
			func(r protoreflect.Message) (string, bool) {
				if r.Descriptor().FullName() != "pomerium.config.GetRouteResponse" {
					return "", false
				}
				return canonicallinks.WithClusterScopeQuery(
					"/app/management/routes/"+canonicallinks.NestedID(r, "route")+"/edit",
					canonicallinks.NestedNamespaceID(r),
				), true
			},
		)
		require.NotNil(t, c)

		out := c(context.Background(), nil, msg, nil)
		assert.Equal(t, map[string]any{
			"links": map[string]any{
				"canonical": "https://console.example.com/app/management/routes/r1/edit?cid=ns-1",
			},
		}, out)
	})

	t.Run("nil when resolver returns ok=false", func(t *testing.T) {
		t.Parallel()
		c := canonicallinks.NewMetaContributor("https://console.example.com",
			func(protoreflect.Message) (string, bool) { return "", false },
		)
		require.NotNil(t, c)
		assert.Nil(t, c(context.Background(), nil, &configpb.GetRouteResponse{}, nil))
	})

	t.Run("nil when resolver returns empty path", func(t *testing.T) {
		t.Parallel()
		c := canonicallinks.NewMetaContributor("https://console.example.com",
			func(protoreflect.Message) (string, bool) { return "", true },
		)
		require.NotNil(t, c)
		assert.Nil(t, c(context.Background(), nil, &configpb.GetRouteResponse{}, nil))
	})

	t.Run("works against dynamicpb message", func(t *testing.T) {
		t.Parallel()
		ns := "ns-1"
		dyn := asDynamic(t, &configpb.GetRouteResponse{
			Route: &configpb.Route{Id: new("r1"), NamespaceId: &ns},
		})
		c := canonicallinks.NewMetaContributor("https://x",
			func(r protoreflect.Message) (string, bool) {
				return "/route/" + canonicallinks.NestedID(r, "route"), true
			},
		)
		out := c(context.Background(), nil, dyn.Interface(), nil)
		assert.Equal(t, "https://x/route/r1", out["links"].(map[string]any)["canonical"])
	})
}
