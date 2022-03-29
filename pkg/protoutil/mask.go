package protoutil

import (
	"github.com/mennanov/fmutils"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// MergeAnyWithFieldMask merges the data in src with the data in dst,
// but only the fields identified by the given mask.
func MergeAnyWithFieldMask(dst, src *anypb.Any, mask *fieldmaskpb.FieldMask) (*anypb.Any, error) {
	if mask == nil {
		return src, nil
	}

	srcMsg, err := src.UnmarshalNew()
	if err != nil {
		return nil, err
	}

	dstMsg, err := dst.UnmarshalNew()
	if err != nil {
		return nil, err
	}

	fmutils.Filter(srcMsg, mask.GetPaths())
	proto.Merge(dstMsg, srcMsg)

	return anypb.New(dstMsg)
}
