package file

import (
	"net/netip"
	"strings"

	"github.com/gaissmai/bart"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

func recordMatches(record *databrokerpb.Record, filter storage.FilterExpression) bool {
	if filter == nil {
		return true
	}

	switch filter := filter.(type) {
	case storage.AndFilterExpression:
		for _, f := range filter {
			if !recordMatches(record, f) {
				return false
			}
		}
		return len(filter) > 0
	case storage.OrFilterExpression:
		for _, f := range filter {
			if recordMatches(record, f) {
				return true
			}
		}
		return false
	case storage.EqualsFilterExpression:
		switch strings.Join(filter.Fields, ".") {
		case "type":
			return record.GetType() == filter.Value
		case "id":
			return record.GetId() == filter.Value
		case "$index":
			if prefix, err := netip.ParsePrefix(filter.Value); err == nil {
				return recordMatchesIPPrefix(record, prefix)
			} else if addr, err := netip.ParseAddr(filter.Value); err == nil {
				return recordMatchesIPAddr(record, addr)
			}
			return false
		default:
			return false
		}
	default:
		return false
	}
}

func recordMatchesIPPrefix(record *databrokerpb.Record, prefix netip.Prefix) bool {
	cidr := storage.GetRecordIndexCIDR(record.GetData())
	if cidr == nil {
		return false
	}

	var tbl bart.Table[struct{}]
	tbl.Insert(*cidr, struct{}{})
	_, ok := tbl.LookupPrefix(prefix)
	return ok
}

func recordMatchesIPAddr(record *databrokerpb.Record, addr netip.Addr) bool {
	cidr := storage.GetRecordIndexCIDR(record.GetData())
	if cidr == nil {
		return false
	}
	var tbl bart.Table[struct{}]
	tbl.Insert(*cidr, struct{}{})
	_, ok := tbl.Lookup(addr)
	return ok
}
