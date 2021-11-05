package cli_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/cli"
	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

type memLS struct {
	data []byte
}

func (s *memLS) Load() ([]byte, error) {
	return s.data, nil
}

func (s *memLS) Save(data []byte) error {
	s.data = data
	return nil
}

func TestLoadSave(t *testing.T) {
	ctx := context.Background()
	ls := new(memLS)

	cfg, err := cli.NewServer(ctx, ls)
	require.NoError(t, err, "load empty config")

	var ids []string
	for _, r := range []*pb.Record{
		{
			Tags: []string{"one"},
			Conn: &pb.Connection{
				Name:       sp("test one"),
				RemoteAddr: "test1.another.domain.com",
				ListenAddr: sp(":9993"),
			},
		},
		{
			Tags: []string{"one", "two"},
			Conn: &pb.Connection{
				Name:       sp("test two"),
				RemoteAddr: "test2.some.domain.com",
				ListenAddr: sp(":9991"),
			},
		},
	} {
		r, err := cfg.Upsert(ctx, r)
		if assert.NoError(t, err) {
			assert.NotNil(t, r.Id)
			ids = append(ids, r.GetId())
		}
	}

	cfg, err = cli.NewServer(ctx, ls)
	require.NoError(t, err, "load config")

	selectors := map[string]*pb.Selector{
		"all": {
			All: true,
		}, "ids": {
			Ids: ids,
		}, "tags": {
			Tags: []string{"one"},
		}}
	for label, s := range selectors {
		recs, err := cfg.List(ctx, s)
		if assert.NoError(t, err, label) && assert.NotNil(t, recs, label) {
			assert.Len(t, recs.Records, len(ids), label)
		}
	}
}

func TestImportExport(t *testing.T) {
	/*
		_, err = cfg.Export(ctx, &pb.ExportRequest{})
		assert.Error(t, err, "export with no args")

		for label, sel := range selectors {
			_, err := cfg.Export(ctx, &pb.ExportRequest{
				Selector: sel,
			})
			assert.NoError(t, err, label)
		}
	*/
}
func sp(txt string) *string {
	return &txt
}
