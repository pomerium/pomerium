package storage_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

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
