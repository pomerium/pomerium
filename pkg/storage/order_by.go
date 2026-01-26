package storage

import (
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/pomerium/pomerium/pkg/protoutil"
)

type OrderByItem struct {
	Field     string
	Ascending bool
}

func (item OrderByItem) String() string {
	if item.Ascending {
		return item.Field
	}
	return "-" + item.Field
}

type OrderBy []OrderByItem

func OrderByFromString(str string) OrderBy {
	var orderBy OrderBy
	for s := range strings.SplitSeq(str, ",") {
		item := OrderByItem{
			Field:     strings.TrimSpace(s),
			Ascending: true,
		}
		if strings.HasPrefix(item.Field, "-") {
			item.Ascending = false
			item.Field = item.Field[1:]
			item.Field = strings.TrimSpace(item.Field)
		}
		if item.Field != "" {
			orderBy = append(orderBy, item)
		}
	}
	return orderBy
}

func (orderBy OrderBy) String() string {
	var sb strings.Builder
	for i, item := range orderBy {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(item.String())
	}
	return sb.String()
}

// SortStable sorts a list of protobuf messages based on the order by.
func Sort[T any, TMsg interface {
	*T
	proto.Message
}](msgs []TMsg, orderBy OrderBy) error {
	compare, err := compareFuncForOrderBy[T, TMsg](orderBy)
	if err != nil {
		return err
	}
	slices.SortFunc(msgs, compare)
	return nil
}

// SortStable sorts (stably) a list of protobuf messages based on the order by.
func SortStable[T any, TMsg interface {
	*T
	proto.Message
}](msgs []TMsg, orderBy OrderBy) error {
	compare, err := compareFuncForOrderBy[T, TMsg](orderBy)
	if err != nil {
		return err
	}
	slices.SortFunc(msgs, compare)
	return nil
}

func compareFuncForOrderBy[T any, TMsg interface {
	*T
	proto.Message
}](orderBy OrderBy) (protoutil.CompareFunc[TMsg], error) {
	fns := make([]protoutil.CompareFunc[TMsg], len(orderBy))
	for i, item := range orderBy {
		compare, err := protoutil.CompareFuncForFieldMask[T, TMsg](&fieldmaskpb.FieldMask{
			Paths: []string{item.Field},
		})
		if err != nil {
			return nil, err
		}
		fns[i] = func(x, y TMsg) int {
			v := compare(x, y)
			if !item.Ascending {
				v = -v
			}
			return v
		}
	}
	return func(x, y TMsg) int {
		for _, fn := range fns {
			v := fn(x, y)
			if v != 0 {
				return v
			}
		}
		return 0
	}, nil
}
