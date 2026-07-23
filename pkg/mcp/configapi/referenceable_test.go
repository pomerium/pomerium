package configapi_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/pomerium/pomerium/config"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/mcp/configapi"
)

// expectedReferenceableFields enumerates every config-proto field that MUST
// carry [(pomerium.config.referenceable) = true]. Adding a referenceable field
// means annotating it in config.proto AND adding it here AND extending
// config.ReferenceableFields — the tests below keep the three in lockstep.
var expectedReferenceableFields = map[string]struct{}{
	"pomerium.config.Route.set_request_headers": {},
}

func referenceable(fd protoreflect.FieldDescriptor) bool {
	v, ok := proto.GetExtension(fd.Options(), configpb.E_Referenceable).(bool)
	return ok && v
}

func collectReferenceable(t *testing.T) map[string]struct{} {
	t.Helper()
	actual := map[string]struct{}{}
	visited := map[protoreflect.FullName]bool{}
	var collect func(protoreflect.MessageDescriptor)
	collect = func(md protoreflect.MessageDescriptor) {
		if visited[md.FullName()] {
			return
		}
		visited[md.FullName()] = true
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			fd := fields.Get(i)
			if referenceable(fd) {
				actual[string(md.FullName())+"."+string(fd.Name())] = struct{}{}
			}
			if fd.Kind() == protoreflect.MessageKind {
				collect(fd.Message())
			}
		}
	}

	svc := configpb.File_config_proto.Services().Get(0)
	if svc == nil {
		t.Fatalf("config.proto exposes no service")
	}
	methods := svc.Methods()
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		collect(m.Input())
		collect(m.Output())
	}
	return actual
}

func TestReferenceableFieldsMatchExpected(t *testing.T) {
	t.Parallel()

	actual := collectReferenceable(t)

	var missing, extra []string
	for path := range expectedReferenceableFields {
		if _, ok := actual[path]; !ok {
			missing = append(missing, path)
		}
	}
	for path := range actual {
		if _, ok := expectedReferenceableFields[path]; !ok {
			extra = append(extra, path)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("fields in expectedReferenceableFields but NOT annotated [(pomerium.config.referenceable) = true]:\n  - %s",
			strings.Join(missing, "\n  - "))
	}
	if len(extra) > 0 {
		t.Errorf("fields annotated [(pomerium.config.referenceable) = true] but NOT in expectedReferenceableFields:\n  - %s",
			strings.Join(extra, "\n  - "))
	}
}

// TestValidatedFieldsAreAnnotatedReferenceable keeps config.ReferenceableFields
// (consulted by the config validator) equal to the set of proto fields
// annotated referenceable, so adding a v2 field forces touching both.
func TestValidatedFieldsAreAnnotatedReferenceable(t *testing.T) {
	t.Parallel()

	annotated := collectReferenceable(t)

	validated := map[string]struct{}{}
	for _, f := range config.ReferenceableFields {
		validated[f] = struct{}{}
	}

	var missing, extra []string
	for path := range validated {
		if _, ok := annotated[path]; !ok {
			missing = append(missing, path)
		}
	}
	for path := range annotated {
		if _, ok := validated[path]; !ok {
			extra = append(extra, path)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("config.ReferenceableFields entries with no (referenceable) proto annotation:\n  - %s",
			strings.Join(missing, "\n  - "))
	}
	if len(extra) > 0 {
		t.Errorf("(referenceable) proto fields missing from config.ReferenceableFields:\n  - %s",
			strings.Join(extra, "\n  - "))
	}
}

func TestIsReferenceable(t *testing.T) {
	t.Parallel()

	route := (&configpb.Route{}).ProtoReflect().Descriptor()
	fields := route.Fields()

	setReqHeaders := fields.ByName("set_request_headers")
	setRespHeaders := fields.ByName("set_response_headers")
	require.NotNil(t, setReqHeaders)
	require.NotNil(t, setRespHeaders)

	assert.True(t, configapi.IsReferenceable(setReqHeaders))
	assert.False(t, configapi.IsReferenceable(setRespHeaders))
}
