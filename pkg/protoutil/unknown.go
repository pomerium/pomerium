package protoutil

import (
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// MarshalUnknownField sets an unknown field on a protobuf message.
func MarshalUnknownField(dst proto.Message, fieldNumber protowire.Number, src proto.Message) error {
	bs, err := (&proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	}).Marshal(src)
	if err != nil {
		return err
	}
	unknown := dst.ProtoReflect().GetUnknown()
	unknown = protowire.AppendTag(unknown, fieldNumber, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, bs)
	dst.ProtoReflect().SetUnknown(unknown)
	return nil
}

// UnmarshalUnknownField unmarshals an unknown field of src into dst.
func UnmarshalUnknownField(src proto.Message, fieldNumber protowire.Number, dst proto.Message) (found bool, err error) {
	var unmarshalError error

	unknown := src.ProtoReflect().GetUnknown()
	for len(unknown) > 0 {
		n, typ, sz := protowire.ConsumeTag(unknown)
		err = protowire.ParseError(sz)
		if err != nil {
			return false, err
		}
		unknown = unknown[sz:]

		// if this is the field we're interested in
		if typ == protowire.BytesType && n == fieldNumber {
			found = true

			bs, sz := protowire.ConsumeBytes(unknown)
			err = protowire.ParseError(sz)
			if err != nil {
				return false, err
			}
			unknown = unknown[sz:]

			unmarshalError = (&proto.UnmarshalOptions{
				AllowPartial: true,
			}).Unmarshal(bs, dst)
		} else {
			// consume the field value and move to the next field
			sz = protowire.ConsumeFieldValue(n, typ, unknown)
			err = protowire.ParseError(sz)
			if err != nil {
				return false, err
			}
			unknown = unknown[sz:]
		}
	}

	return found, unmarshalError
}
