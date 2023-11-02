package storage

import (
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// PatchRecord extracts the data from existing and record, updates the existing
// data subject to the provided field mask, and stores the result back into
// record. The existing record is not modified.
func PatchRecord(existing, record *databroker.Record, fields *fieldmaskpb.FieldMask) error {
	dst, err := existing.GetData().UnmarshalNew()
	if err != nil {
		return fmt.Errorf("could not unmarshal existing record data: %w", err)
	}

	src, err := record.GetData().UnmarshalNew()
	if err != nil {
		return fmt.Errorf("could not unmarshal new record data: %w", err)
	}

	if err := protoutil.OverwriteMasked(dst, src, fields); err != nil {
		return fmt.Errorf("cannot patch record: %w", err)
	}

	record.Data, err = anypb.New(dst)
	if err != nil {
		return fmt.Errorf("could not marshal new record data: %w", err)
	}
	return nil
}
