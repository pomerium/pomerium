package cli

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func importRecords(dst *config, req *pb.ImportRequest) error {
	any := new(anypb.Any)
	if err := protojson.Unmarshal(req.Data, any); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	records := new(pb.Records)
	if err := anypb.UnmarshalTo(any, records, proto.UnmarshalOptions{}); err != nil {
		return fmt.Errorf("unmarshal to: %w", err)
	}

	for _, r := range records.Records {
		if req.OverrideTag != nil {
			r.Tags = []string{*req.OverrideTag}
		}
		// TODO: add deduplication
		dst.upsert(r)
	}

	return nil
}

func exportRecords(recs []*pb.Record, removeTags bool, opts protojson.MarshalOptions) ([]byte, error) {
	rec := proto.Clone(&pb.Records{Records: recs}).(*pb.Records)
	for _, r := range rec.Records {
		r.Id = nil
		if removeTags {
			r.Tags = nil
		}
	}

	any := protoutil.NewAny(rec)
	return opts.Marshal(any)
}
