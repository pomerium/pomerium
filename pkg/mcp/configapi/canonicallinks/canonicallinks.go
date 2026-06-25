// Package canonicallinks provides a small, reusable building block for
// configapi.MetaContributor implementations that emit links.canonical entries
// pointing at a product-specific admin UI.
//
// Pomerium products (zero, console, ...) each expose a Streamable-HTTP MCP
// server that wraps configapi.NewHandler. Every product wants the same
// behavior on every successful tool result: append _meta.links.canonical so
// the LLM (and downstream UI) can hand the user a deep link into the admin
// console for the entity that was just read or written. The URL templates and
// base hostname are product-specific, but the wiring (descriptor-based
// dispatch, dynamicpb-aware extraction, optional ?cid= scoping) is identical.
//
// Typical usage from a product:
//
//	contrib := canonicallinks.NewMetaContributor(
//	    "https://console.example.com",
//	    func(r protoreflect.Message) (string, bool) {
//	        switch r.Descriptor().FullName() {
//	        case "pomerium.config.GetRouteResponse",
//	            "pomerium.config.CreateRouteResponse",
//	            "pomerium.config.UpdateRouteResponse":
//	            id := canonicallinks.NestedID(r, "route")
//	            if id == "" {
//	                return "", false
//	            }
//	            return canonicallinks.WithClusterScopeQuery(
//	                "/app/management/routes/"+id+"/edit",
//	                canonicallinks.NestedNamespaceID(r),
//	            ), true
//	        }
//	        return "", false
//	    },
//	)
//	handler := configapi.NewHandler(inner, configapi.WithMetaContributor(contrib))
package canonicallinks

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/pomerium/pomerium/pkg/mcp/configapi"
)

// Resolver maps a config-service response message to a URL path under the
// product's admin-UI base, and returns ok==true when the response identifies
// a navigable entity. Returning ("", false) is the conventional way to skip
// responses without a deep link (List*, Delete*, anything unfamiliar); the
// contributor returns nil for those, leaving the response unchanged.
//
// Implementations must dispatch on r.Descriptor().FullName() rather than via
// Go type assertion: configapi instantiates response messages via
// dynamicpb.NewMessage so a type assertion to a concrete *configpb.* type
// will fail. See the contract on configapi.MetaContributor.
type Resolver func(r protoreflect.Message) (urlPath string, ok bool)

// NewMetaContributor returns a configapi.MetaContributor that appends
// _meta.links.canonical = baseURL + resolver(...) on every successful tool
// result whose response the resolver recognises. baseURL must not have a
// trailing slash; the resolver returns paths beginning with "/".
//
// Returns nil when baseURL is empty or resolver is nil — passing nil into
// configapi.WithMetaContributor is a documented no-op, so callers can pipe
// the result through unconditionally without an explicit guard.
func NewMetaContributor(baseURL string, resolve Resolver) configapi.MetaContributor {
	if baseURL == "" || resolve == nil {
		return nil
	}
	return func(_ context.Context, _ protoreflect.MethodDescriptor, msg proto.Message, _ []string) map[string]any {
		if msg == nil {
			return nil
		}
		path, ok := resolve(msg.ProtoReflect())
		if !ok || path == "" {
			return nil
		}
		return map[string]any{
			"links": map[string]any{
				"canonical": baseURL + path,
			},
		}
	}
}

// NestedID returns the value of msg.<wrapperField>.id where wrapperField is a
// proto field name in snake_case (e.g. "route", "policy", "service_account").
// Returns "" when the wrapper field is absent or unset, or when the wrapper
// message has no id field set. Both fields are addressed by proto name, which
// is stable across descriptor instances.
//
// Example: on a GetRouteResponse, NestedID(r, "route") returns the route id.
func NestedID(r protoreflect.Message, wrapperField string) string {
	if !r.IsValid() {
		return ""
	}
	wrapperFD := r.Descriptor().Fields().ByName(protoreflect.Name(wrapperField))
	if wrapperFD == nil || !r.Has(wrapperFD) {
		return ""
	}
	wrapper := r.Get(wrapperFD).Message()
	idFD := wrapper.Descriptor().Fields().ByName("id")
	if idFD == nil || !wrapper.Has(idFD) {
		return ""
	}
	return wrapper.Get(idFD).String()
}

// NestedNamespaceID searches msg for a singular nested entity message that
// carries a namespace_id field, and returns its value. Iteration is by
// descriptor reflection so adding a new entity type does not require updating
// this function. Returns "" when no nested namespace_id is set.
//
// Typical use: a Resolver that scopes canonical URLs to the right cluster via
// WithClusterScopeQuery on the result.
func NestedNamespaceID(r protoreflect.Message) string {
	if !r.IsValid() {
		return ""
	}
	var found string
	r.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() != protoreflect.MessageKind || fd.IsList() || fd.IsMap() {
			return true
		}
		nsFD := v.Message().Descriptor().Fields().ByName("namespace_id")
		if nsFD == nil || !v.Message().Has(nsFD) {
			return true
		}
		found = v.Message().Get(nsFD).String()
		return false
	})
	return found
}

// WithClusterScopeQuery appends ?cid=<cid> to rawURL (or &cid=<cid> if rawURL
// already contains a query string), so the admin UI lands on the cluster the
// entity belongs to. Returns rawURL unchanged when cid is empty.
func WithClusterScopeQuery(rawURL, cid string) string {
	if cid == "" {
		return rawURL
	}
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + url.Values{"cid": []string{cid}}.Encode()
}

// EntityPath formats an admin-UI path for an entity nested under wrapperField,
// optionally appending ?cid=<namespace_id> when the entity carries one. pathFmt
// must contain exactly one %s verb for the entity id. Returns ("", false) when
// the wrapper has no id (typically a response that didn't surface the id we
// expected). Callers that don't want cluster scoping should use NestedID
// directly and skip this helper.
func EntityPath(r protoreflect.Message, pathFmt, wrapperField string) (string, bool) {
	id := NestedID(r, wrapperField)
	if id == "" {
		return "", false
	}
	return WithClusterScopeQuery(fmt.Sprintf(pathFmt, id), NestedNamespaceID(r)), true
}
