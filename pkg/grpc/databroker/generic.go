package databroker

import (
	"google.golang.org/protobuf/proto"
)

type GenericRecord[T proto.Message] struct {
	*Record
	Object T
}
