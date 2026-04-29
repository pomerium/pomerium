package configapi_test

import (
	"regexp"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// sensitiveNamePattern flags field names that look like they hold secret
// material. Any field whose name matches this pattern but is not annotated
// with [(pomerium.config.sensitive) = true] fails the lint and must be
// either annotated or added to the allowlist below with a justification.
var sensitiveNamePattern = regexp.MustCompile(
	`(?i)(^|_)(secret|password|credential|signing_key|private_key|access_token)($|_)`,
)

// nonSensitiveAllowlist lists field paths whose names happen to match the
// sensitive pattern but do not actually carry secrets. Use sparingly and
// document the reason inline.
var nonSensitiveAllowlist = map[string]string{
	"pomerium.config.Route.idp_access_token_allowed_audiences":    "list of allowed audiences, not a token",
	"pomerium.config.Settings.idp_access_token_allowed_audiences": "list of allowed audiences, not a token",
}

// TestSensitiveAnnotationsCoverField fails when a ConfigService request or
// response message reaches a field whose name suggests sensitivity but lacks
// the [(pomerium.config.sensitive) = true] annotation. New options that
// match the pattern must be either annotated or explicitly allowlisted.
func TestSensitiveAnnotationsCoverField(t *testing.T) {
	t.Parallel()

	svc := configpb.File_config_proto.Services().Get(0)
	if svc == nil {
		t.Fatalf("config.proto exposes no service")
	}

	visited := map[protoreflect.FullName]bool{}
	var problems []string

	methods := svc.Methods()
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		walk(m.Input(), visited, &problems)
		walk(m.Output(), visited, &problems)
	}

	if len(problems) > 0 {
		t.Fatalf(
			"the following fields look sensitive but are not annotated with"+
				" [(pomerium.config.sensitive) = true]:\n  - %s",
			strings.Join(problems, "\n  - "),
		)
	}
}

func walk(md protoreflect.MessageDescriptor, visited map[protoreflect.FullName]bool, problems *[]string) {
	if visited[md.FullName()] {
		return
	}
	visited[md.FullName()] = true
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		name := string(fd.Name())
		path := string(md.FullName()) + "." + name
		if sensitiveNamePattern.MatchString(name) {
			if _, ok := nonSensitiveAllowlist[path]; !ok && !sensitive(fd) {
				*problems = append(*problems, path)
			}
		}
		if fd.Kind() == protoreflect.MessageKind {
			walk(fd.Message(), visited, problems)
		}
	}
}

func sensitive(fd protoreflect.FieldDescriptor) bool {
	v, ok := proto.GetExtension(fd.Options(), configpb.E_Sensitive).(bool)
	return ok && v
}
