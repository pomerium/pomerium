package storage_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestOrderBy(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		input  string
		expect storage.OrderBy
	}{
		{
			"",
			nil,
		},
		{
			"id",
			storage.OrderBy{{Field: "id", Ascending: true}},
		},
		{
			"             ",
			nil,
		},
		{
			" , , , , ,   , ",
			nil,
		},
		{
			"   -  id ",
			storage.OrderBy{{Field: "id"}},
		},
		{
			"id,-type,data.name",
			storage.OrderBy{
				{Field: "id", Ascending: true},
				{Field: "type"},
				{Field: "data.name", Ascending: true},
			},
		},
	} {
		actual := storage.OrderByFromString(tc.input)
		assert.Equal(t, tc.expect, actual,
			"input: '%s', expect: '%s', actual: '%s'",
			tc.input, tc.expect, actual)
	}
}

func TestSort(t *testing.T) {
	t.Parallel()

	ci1 := &config.CertificateInfo{Version: 3, Serial: "a"}
	ci2 := &config.CertificateInfo{Version: 1, Serial: "b"}
	ci3 := &config.CertificateInfo{Version: 2, Serial: "a"}
	ci4 := &config.CertificateInfo{Version: 1, Serial: "a"}
	msgs := []*config.CertificateInfo{ci1, ci2, ci3, ci4}
	storage.SortStable(msgs, storage.OrderByFromString("serial,-version"))
	assert.Equal(t, []*config.CertificateInfo{ci1, ci3, ci4, ci2}, msgs)
}
