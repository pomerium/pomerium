// Package cli implements api for pomerium desktop UI
package cli

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

var (
	errTagIndexInconsistent = errors.New("tag index inconsistent. this is a bug")
)

type config struct {
	byID  map[string]*pb.Record
	byTag map[string]map[string]*pb.Record
}

func newConfig() *config {
	return &config{
		byID:  make(map[string]*pb.Record),
		byTag: make(map[string]map[string]*pb.Record),
	}
}

func loadConfig(ls ConfigProvider) (*config, error) {
	data, err := ls.Load()
	if err != nil {
		return nil, fmt.Errorf("load: %w", err)
	}

	cfg := newConfig()

	if len(data) == 0 {
		return cfg, nil
	}

	any := new(anypb.Any)
	if err = protojson.Unmarshal(data, any); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	records := new(pb.Records)
	if err = anypb.UnmarshalTo(any, records, proto.UnmarshalOptions{}); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	for _, r := range records.Records {
		cfg.upsert(r)
	}

	return cfg, nil
}

func (cfg *config) save(ls ConfigProvider) error {
	records := make([]*pb.Record, 0, len(cfg.byID))
	for _, rec := range cfg.byID {
		records = append(records, rec)
	}

	any := protoutil.NewAny(&pb.Records{Records: records})
	data, err := protojson.MarshalOptions{}.Marshal(any)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if err = ls.Save(data); err != nil {
		return fmt.Errorf("save: %w", err)
	}

	return nil
}

func (cfg *config) clearTags(r *pb.Record) error {
	if r.Id == nil {
		return nil // new record
	}

	id := r.GetId()
	current, ok := cfg.byID[id]
	if !ok {
		return fmt.Errorf("expect record id=%s be in byID", id)
	}

	for _, t := range current.Tags {
		m, ok := cfg.byTag[t]
		if !ok {
			return fmt.Errorf("expect record id=%s with tag=%s be in byTag", id, t)
		}
		if _, ok = m[r.GetId()]; !ok {
			return fmt.Errorf("expect record id=%s with tag=%s be in byTag[]byID", id, t)
		}
		delete(m, id)
	}

	return nil
}

func (cfg *config) upsert(r *pb.Record) {
	var id = r.GetId()
	if r.Id == nil {
		id = uuid.NewString()
		r.Id = &id
	}

	current := cfg.byID[id]
	if current != nil && r.Conn == nil {
		r.Conn = current.Conn
	}
	cfg.byID[id] = r
	for _, t := range r.Tags {
		m := cfg.byTag[t]
		if m == nil {
			m = make(map[string]*pb.Record)
			cfg.byTag[t] = m
		}
		m[id] = r
	}
}

func (cfg *config) delete(id string) error {
	rec, ok := cfg.byID[id]
	if !ok {
		return errNotFound
	}

	delete(cfg.byID, id)
	for _, tag := range rec.GetTags() {
		m := cfg.byTag[tag]
		if m == nil {
			return errTagIndexInconsistent
		}
		delete(m, id)
		if len(m) == 0 {
			delete(cfg.byTag, tag)
		}
	}

	return nil
}

func (cfg *config) listAll() []*pb.Record {
	records := make([]*pb.Record, 0, len(cfg.byID))
	for _, r := range cfg.byID {
		records = append(records, r)
	}
	return records
}

func (cfg *config) listByIDs(ids []string) ([]*pb.Record, error) {
	var records []*pb.Record
	for _, id := range ids {
		r, ok := cfg.byID[id]
		if !ok {
			return nil, status.Error(codes.NotFound, id)
		}
		records = append(records, r)
	}
	return records, nil
}

func (cfg *config) listByTags(tags []string) ([]*pb.Record, error) {
	var records []*pb.Record
	for _, tag := range tags {
		m, ok := cfg.byTag[tag]
		if !ok {
			return nil, status.Error(codes.NotFound, tag)
		}
		for _, r := range m {
			records = append(records, r)
		}
	}
	return records, nil
}

func (cfg *config) getTags() []string {
	tags := make([]string, 0, len(cfg.byTag))
	for tag := range cfg.byTag {
		tags = append(tags, tag)
	}
	return tags
}
