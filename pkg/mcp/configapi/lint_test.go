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

// expectedSensitiveFields enumerates every config-proto field that MUST
// carry [(pomerium.config.sensitive) = true]. The corresponding lint
// (TestSensitiveFieldsMatchExpected) is the load-bearing defense against
// accidental annotation removal: a regex-based check is too coarse to
// catch every shape (e.g. `jwt`, `key_bytes`, `tls_client_key`,
// `kubernetes_service_account_token`, `ssh_host_keys`) without
// allowlisting dozens of unrelated `_key_pair_id` / `_token_file` fields.
//
// Adding a new sensitive field: annotate it in config.proto AND add its
// fully-qualified name here. Removing the annotation (legitimate
// declassification): remove from this set. The two operations always go
// together — that's the lint's whole purpose.
var expectedSensitiveFields = map[string]struct{}{
	"pomerium.config.Route.tls_client_key":                   {},
	"pomerium.config.Route.kubernetes_service_account_token": {},
	"pomerium.config.Route.idp_client_secret":                {},
	"pomerium.config.UpstreamOAuth2.client_secret":           {},
	"pomerium.config.Settings.Certificate.key_bytes":         {},
	"pomerium.config.Settings.shared_secret":                 {},
	"pomerium.config.Settings.cookie_secret":                 {},
	"pomerium.config.Settings.idp_client_secret":             {},
	"pomerium.config.Settings.signing_key":                   {},
	"pomerium.config.Settings.autocert_eab_key_id":           {},
	"pomerium.config.Settings.autocert_eab_mac_key":          {},
	"pomerium.config.Settings.ssh_host_keys":                 {},
	"pomerium.config.Settings.ssh_user_ca_key":               {},
	"pomerium.config.KeyPair.key":                            {},
	"pomerium.config.CreateServiceAccountResponse.jwt":       {},
	"pomerium.config.UpdateServiceAccountResponse.jwt":       {},
}

// TestSensitiveFieldsMatchExpected is the explicit-set complement to
// TestSensitiveAnnotationsCoverField. The regex test catches "you added a
// new field that LOOKS sensitive but didn't annotate it"; this test
// catches "you removed [(sensitive) = true] from a field we already know
// is sensitive". Both are required: the regex misses obviously-sensitive
// names like `jwt` or `tls_client_key` (no `secret`/`token` token), and
// any pattern broad enough to catch them collapses into a sea of
// false-positive `_key_pair_id` / `_key_file` allowlist entries.
func TestSensitiveFieldsMatchExpected(t *testing.T) {
	t.Parallel()

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
			if sensitive(fd) {
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

	var missing, extra []string
	for path := range expectedSensitiveFields {
		if _, ok := actual[path]; !ok {
			missing = append(missing, path)
		}
	}
	for path := range actual {
		if _, ok := expectedSensitiveFields[path]; !ok {
			extra = append(extra, path)
		}
	}
	if len(missing) > 0 {
		t.Errorf(
			"the following fields are in expectedSensitiveFields but are NOT "+
				"annotated [(pomerium.config.sensitive) = true]:\n  - %s\n"+
				"either add the annotation or remove the entry from the set",
			strings.Join(missing, "\n  - "),
		)
	}
	if len(extra) > 0 {
		t.Errorf(
			"the following fields ARE annotated [(pomerium.config.sensitive) "+
				"= true] but are NOT in expectedSensitiveFields:\n  - %s\n"+
				"add them to the set if their annotation is intentional",
			strings.Join(extra, "\n  - "),
		)
	}
}
