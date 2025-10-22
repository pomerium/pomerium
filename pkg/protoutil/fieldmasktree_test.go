package protoutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestFieldMaskTree(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		tr := newFieldMaskTree(&fieldmaskpb.FieldMask{})
		assert.Equal(t, fieldMaskTree(nil), tr)
	})
	t.Run("basic", func(t *testing.T) {
		tr := newFieldMaskTree(&fieldmaskpb.FieldMask{
			Paths: []string{"foo", "bar", "baz"},
		})
		assert.Equal(t, fieldMaskTree{
			"foo": {},
			"bar": {},
			"baz": {},
		}, tr)
	})
	t.Run("nested", func(t *testing.T) {
		tr := newFieldMaskTree(&fieldmaskpb.FieldMask{
			Paths: []string{"foo.bar.baz", "foo.bar.xyz", "foo.quux"},
		})
		assert.Equal(t, fieldMaskTree{
			"foo": {
				"bar": {
					"baz": {},
					"xyz": {},
				},
				"quux": {},
			},
		}, tr)
	})
	t.Run("overlapping fields 1", func(t *testing.T) {
		tr := newFieldMaskTree(&fieldmaskpb.FieldMask{
			Paths: []string{"foo", "foo.bar"},
		})
		assert.Equal(t, fieldMaskTree{
			"foo": {},
		}, tr)
	})
	t.Run("overlapping fields 2", func(t *testing.T) {
		tr := newFieldMaskTree(&fieldmaskpb.FieldMask{
			Paths: []string{"foo.bar", "foo"},
		})
		assert.Equal(t, fieldMaskTree{
			"foo": {},
		}, tr)
	})
}
