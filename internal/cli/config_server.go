package cli

import (
	"context"
	"errors"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

type configServer struct {
	sync.Locker
	ConfigProvider
	*config
}

var _ pb.ConfigServer = &configServer{}

var errNotFound = errors.New("not found")

func (s *configServer) List(_ context.Context, sel *pb.Selector) (*pb.Records, error) {
	s.Lock()
	defer s.Unlock()

	records, err := s.listLocked(sel)
	if err != nil {
		return nil, err
	}
	return &pb.Records{Records: records}, nil
}

func (s *configServer) listLocked(sel *pb.Selector) ([]*pb.Record, error) {
	if sel.GetAll() {
		return s.config.listAll(), nil
	} else if len(sel.GetIds()) > 0 {
		return s.config.listByIDs(sel.GetIds())
	} else if len(sel.GetTags()) > 0 {
		return s.config.listByTags(sel.GetTags())
	}
	return nil, status.Error(codes.InvalidArgument, "either all, ids or tags filter must be specified")
}

func (s *configServer) Delete(_ context.Context, sel *pb.Selector) (*pb.DeleteRecordsResponse, error) {
	s.Lock()
	defer s.Unlock()

	recs, err := s.listLocked(sel)
	if err != nil {
		return nil, err
	}

	for _, r := range recs {
		if err = s.config.delete(r); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	return &pb.DeleteRecordsResponse{}, nil
}

func (s *configServer) Upsert(_ context.Context, r *pb.Record) (*pb.Record, error) {
	s.Lock()
	defer s.Unlock()

	if err := s.config.clearTags(r); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.config.upsert(r)
	if err := s.config.save(s.ConfigProvider); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return r, nil
}

func (s *configServer) Export(ctx context.Context, req *pb.ExportRequest) (*pb.ConfigData, error) {
	s.Lock()
	defer s.Unlock()

	recs, err := s.listLocked(req.Selector)
	if err != nil {
		return nil, err
	}

	opts := protojson.MarshalOptions{}
	if req.Format == pb.ExportRequest_EXPORT_FORMAT_JSON_PRETTY {
		opts.Multiline = true
		opts.Indent = "  "
	}
	data, err := exportRecords(recs, req.RemoveTags, opts)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.ConfigData{Data: data}, nil
}

func (s *configServer) Import(_ context.Context, req *pb.ImportRequest) (*pb.ImportResponse, error) {
	s.Lock()
	defer s.Unlock()

	if err := importRecords(s.config, req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.ImportResponse{}, nil
}
