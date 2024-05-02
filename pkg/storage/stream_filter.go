package storage

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// A RecordStreamFilter filters a RecordStream.
type RecordStreamFilter func(record *databroker.Record) (keep bool)

// And creates a new RecordStreamFilter by applying both functions to a record.
func (filter RecordStreamFilter) And(
	then RecordStreamFilter,
) RecordStreamFilter {
	return func(record *databroker.Record) (keep bool) {
		return filter(record) && then(record)
	}
}

// FilteredRecordStreamGenerator creates a RecordStreamGenerator that only returns records that pass the filter.
func FilteredRecordStreamGenerator(
	generator RecordStreamGenerator,
	filter RecordStreamFilter,
) RecordStreamGenerator {
	return func(ctx context.Context, block bool) (*databroker.Record, error) {
		for {
			record, err := generator(ctx, block)
			if err != nil {
				return nil, err
			}

			if !filter(record) {
				continue
			}

			return record, nil
		}
	}
}

// RecordStreamFilterFromFilterExpression returns a RecordStreamFilter from a FilterExpression.
func RecordStreamFilterFromFilterExpression(
	expr FilterExpression,
) (filter RecordStreamFilter, err error) {
	if expr == nil {
		return func(_ *databroker.Record) (keep bool) { return true }, nil
	}

	switch expr := expr.(type) {
	case AndFilterExpression:
		if len(expr) == 0 {
			return func(_ *databroker.Record) (keep bool) { return true }, nil
		}

		fs := make([]RecordStreamFilter, len(expr))
		for i, e := range expr {
			fs[i], err = RecordStreamFilterFromFilterExpression(e)
			if err != nil {
				return nil, err
			}
		}
		return func(record *databroker.Record) (keep bool) {
			for _, f := range fs {
				if !f(record) {
					return false
				}
			}
			return true
		}, nil
	case OrFilterExpression:
		if len(expr) == 0 {
			return func(_ *databroker.Record) (keep bool) { return true }, nil
		}

		fs := make([]RecordStreamFilter, len(expr))
		for i, e := range expr {
			fs[i], err = RecordStreamFilterFromFilterExpression(e)
			if err != nil {
				return nil, err
			}
		}
		return func(record *databroker.Record) (keep bool) {
			for _, f := range fs {
				if f(record) {
					return true
				}
			}
			return false
		}, nil
	case EqualsFilterExpression:
		switch strings.Join(expr.Fields, ".") {
		case "id":
			id := expr.Value
			return func(record *databroker.Record) (keep bool) {
				return record.GetId() == id
			}, nil
		case "$index":
			ip, _ := netip.ParseAddr(expr.Value)
			return func(record *databroker.Record) (keep bool) {
				// indexed via CIDR
				if ip.IsValid() {
					msg, _ := record.GetData().UnmarshalNew()
					cidr := GetRecordIndexCIDR(msg)
					if cidr != nil && cidr.Contains(ip) {
						return true
					}
				}

				return false
			}, nil
		default:
			return nil, fmt.Errorf("only id or $index are supported for query filters")
		}
	default:
		panic(fmt.Sprintf("unsupported filter expression type: %T", expr))
	}
}
