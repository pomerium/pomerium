package configapi

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// IsReferenceable reports whether fd carries the
// (pomerium.config.referenceable) option, meaning its string values may embed
// ${secret.ID} references. Resolution time is field-specific.
func IsReferenceable(fd protoreflect.FieldDescriptor) bool {
	v, ok := proto.GetExtension(fd.Options(), configpb.E_Referenceable).(bool)
	return ok && v
}
