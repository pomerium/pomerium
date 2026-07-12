package session_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// TestSensitiveFieldAnnotations verifies that fields carrying secret
// material are annotated with [(pomerium.config.sensitive) = true] so they
// are redacted wherever sensitive-aware tooling (e.g. the databroker debug
// browser) renders session records.
func TestSensitiveFieldAnnotations(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		msg   proto.Message
		field protoreflect.Name
	}{
		{&session.OAuthToken{}, "access_token"},
		{&session.OAuthToken{}, "refresh_token"},
		{&session.IDToken{}, "raw"},
	} {
		fd := tc.msg.ProtoReflect().Descriptor().Fields().ByName(tc.field)
		if assert.NotNil(t, fd, "field %s not found", tc.field) {
			assert.True(t, protoutil.IsSensitive(fd),
				"%s.%s must be annotated [(pomerium.config.sensitive) = true]",
				tc.msg.ProtoReflect().Descriptor().FullName(), tc.field)
		}
	}
}
