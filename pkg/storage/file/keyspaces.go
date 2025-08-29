package file

import (
	"bytes"
	"fmt"
	"iter"
	"time"

	"github.com/cockroachdb/pebble/v2"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/pebbleutil"
)

// pebble is an ordered key-value database
// we break up keys into various keyspaces

const (
	prefixUnusedKeySpace = iota
	prefixLeaseKeySpace
	prefixMetadataKeySpace
	prefixOptionsKeySpace
	prefixRecordChangeKeySpace
	prefixRecordChangeIndexByTypeKeySpace
	prefixRecordKeySpace
	prefixRecordIndexByTypeVersionKeySpace
	prefixRegistryServiceKeySpace
)

// lease:
//   keys: prefix-lease | {leaseName as bytes}
//   values: {leaseID as bytes} | 0x00 | {expiresAt as timestamp}

type leaseKeySpaceType struct{}

var leaseKeySpace leaseKeySpaceType

func (ks leaseKeySpaceType) encodeKey(leaseName string) []byte {
	return encodeSimpleKey(prefixLeaseKeySpace, []byte(leaseName))
}

func (ks leaseKeySpaceType) encodeValue(leaseID string, expiresAt time.Time) []byte {
	return encodeLeaseValue(leaseValue{id: leaseID, expiresAt: expiresAt})
}

func (ks leaseKeySpaceType) get(r reader, leaseName string) (leaseID string, expiresAt time.Time, err error) {
	value, err := pebbleGet(r, ks.encodeKey(leaseName), decodeLeaseValue)
	if err != nil {
		return leaseID, expiresAt, err
	}
	return value.id, value.expiresAt, nil
}

func (ks leaseKeySpaceType) set(w writer, leaseName, leaseID string, expiresAt time.Time) error {
	return pebbleSet(w, ks.encodeKey(leaseName), ks.encodeValue(leaseID, expiresAt))
}

// metadata:
//   serverVersion:
//     key: prefix-metadata | 0x01
//     value: {serverVersion as uint64}
//   migration:
//     key: prefix-metadata | 0x02
//     value: {migration as uint64}

type metadataKeySpaceType struct{}

var metadataKeySpace metadataKeySpaceType

func (ks metadataKeySpaceType) encodeServerVersionKey() []byte {
	return encodeSimpleKey(prefixMetadataKeySpace, []byte{0x01})
}

func (ks metadataKeySpaceType) encodeMigrationKey() []byte {
	return encodeSimpleKey(prefixMetadataKeySpace, []byte{0x02})
}

func (ks metadataKeySpaceType) getServerVersion(r reader) (uint64, error) {
	return pebbleGet(r, ks.encodeServerVersionKey(), decodeUint64)
}

func (ks metadataKeySpaceType) getMigration(r reader) (uint64, error) {
	return pebbleGet(r, ks.encodeMigrationKey(), decodeUint64)
}

func (ks metadataKeySpaceType) setServerVersion(w writer, serverVersion uint64) error {
	return pebbleSet(w, ks.encodeServerVersionKey(), encodeUint64(serverVersion))
}

func (ks metadataKeySpaceType) setMigration(w writer, migration uint64) error {
	return pebbleSet(w, ks.encodeMigrationKey(), encodeUint64(migration))
}

// options:
//   keys: prefix-options | {recordType as bytes}
//   values: {options as proto}

type optionsKeySpaceType struct{}

var optionsKeySpace optionsKeySpaceType

func (ks optionsKeySpaceType) bounds() (lowerBound, upperBound []byte) {
	prefix := []byte{prefixOptionsKeySpace}
	return prefix, pebbleutil.PrefixToUpperBound(prefix)
}

func (ks optionsKeySpaceType) decodeKey(data []byte) (string, error) {
	if !bytes.HasPrefix(data, []byte{prefixOptionsKeySpace}) {
		return "", fmt.Errorf("invalid key, expected options prefix")
	}
	data = data[1:]

	return string(data), nil
}

func (ks optionsKeySpaceType) decodeValue(data []byte) (*databrokerpb.Options, error) {
	return decodeProto[databrokerpb.Options](data)
}

func (ks optionsKeySpaceType) delete(w writer, recordType string) error {
	return pebbleDelete(w, ks.encodeKey(recordType))
}

func (optionsKeySpaceType) deleteAll(w writer) error {
	return pebbleDeletePrefix(w, []byte{prefixOptionsKeySpace})
}

func (ks optionsKeySpaceType) encodeKey(recordType string) []byte {
	return encodeSimpleKey(prefixOptionsKeySpace, []byte(recordType))
}

func (ks optionsKeySpaceType) encodeValue(options *databrokerpb.Options) []byte {
	return encodeProto(options)
}

func (ks optionsKeySpaceType) iterate(r reader) iter.Seq2[optionsNode, error] {
	return func(yield func(optionsNode, error) bool) {
		opts := &pebble.IterOptions{}
		opts.LowerBound, opts.UpperBound = ks.bounds()

		for node, err := range pebbleutil.Iterate(r, opts, func(it *pebble.Iterator) (node optionsNode, err error) {
			node.recordType, err = ks.decodeKey(it.Key())
			if err != nil {
				return node, err
			}
			node.options, err = ks.decodeValue(it.Value())
			if err != nil {
				return node, err
			}
			return node, nil
		}) {
			if !yield(node, err) {
				return
			}
		}
	}
}

func (ks optionsKeySpaceType) set(w writer, recordType string, options *databrokerpb.Options) error {
	return pebbleSet(w, ks.encodeKey(recordType), ks.encodeValue(options))
}

// record:
//   keys: prefix-record | {recordType as bytes} | 0x00 | {recordID as bytes}
//   values: {record as proto}

type recordKeySpaceType struct{}

var recordKeySpace recordKeySpaceType

func (ks recordKeySpaceType) bounds() (lowerBound, upperBound []byte) {
	prefix := encodeSimpleKey(prefixRecordKeySpace, nil)
	return prefix, pebbleutil.PrefixToUpperBound(prefix)
}

func (ks recordKeySpaceType) boundsForRecordType(recordType string) (lowerBound, upperBound []byte) {
	prefix := encodeJoinedKey(prefixRecordKeySpace, []byte(recordType), nil)
	return prefix, pebbleutil.PrefixToUpperBound(prefix)
}

func (ks recordKeySpaceType) decodeKey(data []byte) (recordType, recordID string, err error) {
	segments, err := decodeJoinedKey(data, prefixRecordKeySpace, 2)
	if err != nil {
		return "", "", err
	}

	return string(segments[0]), string(segments[1]), nil
}

func (ks recordKeySpaceType) decodeValue(data []byte) (*databrokerpb.Record, error) {
	return decodeProto[databrokerpb.Record](data)
}

func (ks recordKeySpaceType) delete(w writer, recordType, recordID string) error {
	return pebbleDelete(w, ks.encodeKey(recordType, recordID))
}

func (recordKeySpaceType) deleteAll(w writer) error {
	return pebbleDeletePrefix(w, []byte{prefixRecordKeySpace})
}

func (ks recordKeySpaceType) encodeKey(recordType, recordID string) []byte {
	return encodeJoinedKey(prefixRecordKeySpace, []byte(recordType), []byte(recordID))
}

func (ks recordKeySpaceType) encodeValue(record *databrokerpb.Record) []byte {
	return encodeProto(record)
}

func (ks recordKeySpaceType) get(r reader, recordType, recordID string) (*databrokerpb.Record, error) {
	return pebbleGet(r, ks.encodeKey(recordType, recordID), ks.decodeValue)
}

func (ks recordKeySpaceType) iterate(r reader, recordType string) iter.Seq2[*databrokerpb.Record, error] {
	return func(yield func(*databrokerpb.Record, error) bool) {
		opts := new(pebble.IterOptions)
		opts.LowerBound, opts.UpperBound = ks.boundsForRecordType(recordType)
		for value, err := range pebbleutil.IterateValues(r, opts) {
			if err != nil {
				yield(nil, err)
				return
			}

			record, err := ks.decodeValue(value)
			if err != nil {
				// skip invalid records
				continue
			}
			if !yield(record, nil) {
				return
			}
		}
	}
}

func (ks recordKeySpaceType) iterateAll(r reader) iter.Seq2[*databrokerpb.Record, error] {
	return func(yield func(*databrokerpb.Record, error) bool) {
		opts := new(pebble.IterOptions)
		opts.LowerBound, opts.UpperBound = ks.bounds()
		for value, err := range pebbleutil.IterateValues(r, opts) {
			if err != nil {
				yield(nil, err)
				return
			}

			record, err := ks.decodeValue(value)
			if err != nil {
				// skip invalid records
				continue
			}
			if !yield(record, nil) {
				return
			}
		}
	}
}

func (ks recordKeySpaceType) iterateTypes(r reader) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		opts := new(pebble.IterOptions)
		opts.LowerBound, opts.UpperBound = ks.bounds()

		var previousRecordType string
		for key, err := range pebbleutil.IterateKeys(r, opts) {
			if err != nil {
				yield("", err)
				return
			}

			recordType, _, err := ks.decodeKey(key)
			if err != nil {
				// skip invalid keys
				continue
			}

			if previousRecordType != "" && recordType == previousRecordType {
				// skip until the record type changes
				continue
			}
			previousRecordType = recordType

			if !yield(recordType, nil) {
				return
			}
		}
	}
}

func (ks recordKeySpaceType) set(w writer, record *databrokerpb.Record) error {
	return pebbleSet(w, ks.encodeKey(record.GetType(), record.GetId()), ks.encodeValue(record))
}

// record-index-by-type-version:
//   keys: prefix-record-index-by-type-version | {recordType as bytes} | 0x00 | {version as uint64}
//   values: {recordID as bytes}

type recordIndexByTypeVersionKeySpaceType struct{}

var recordIndexByTypeVersionKeySpace recordIndexByTypeVersionKeySpaceType

func (ks recordIndexByTypeVersionKeySpaceType) bounds(recordType string) ([]byte, []byte) {
	prefix := encodeJoinedKey(prefixRecordIndexByTypeVersionKeySpace, []byte(recordType), []byte{})
	return prefix, pebbleutil.PrefixToUpperBound(prefix)
}

func (ks recordIndexByTypeVersionKeySpaceType) decodeValue(data []byte) string {
	return string(data)
}

func (ks recordIndexByTypeVersionKeySpaceType) encodeKey(recordType string, version uint64) []byte {
	return encodeJoinedKey(prefixRecordIndexByTypeVersionKeySpace,
		[]byte(recordType),
		encodeUint64(version))
}

func (ks recordIndexByTypeVersionKeySpaceType) encodeValue(recordID string) []byte {
	return []byte(recordID)
}

func (ks recordIndexByTypeVersionKeySpaceType) delete(w writer, recordType string, version uint64) error {
	return pebbleDelete(w, ks.encodeKey(recordType, version))
}

func (recordIndexByTypeVersionKeySpaceType) deleteAll(w writer) error {
	return pebbleDeletePrefix(w, []byte{prefixRecordIndexByTypeVersionKeySpace})
}

func (ks recordIndexByTypeVersionKeySpaceType) iterateIDsReversed(r reader, recordType string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		opts := &pebble.IterOptions{}
		opts.LowerBound, opts.UpperBound = ks.bounds(recordType)
		it, err := r.NewIter(opts)
		if err != nil {
			yield("", err)
			return
		}

		for ok := it.Last(); ok; ok = it.Prev() {
			if !yield(ks.decodeValue(it.Value()), nil) {
				_ = it.Close()
				return
			}
		}
		err = it.Close()
		if err != nil {
			yield("", err)
			return
		}
	}
}

func (ks recordIndexByTypeVersionKeySpaceType) set(w writer, recordType, recordID string, version uint64) error {
	return pebbleSet(w, ks.encodeKey(recordType, version), ks.encodeValue(recordID))
}

// record-change:
//	keys: prefix-record-change | {version as uint64}
//	values: {record as proto}

type recordChangeKeySpaceType struct{}

var recordChangeKeySpace recordChangeKeySpaceType

func (ks recordChangeKeySpaceType) bounds(afterRecordVersion uint64) (lowerBound, upperBound []byte) {
	return encodeSimpleKey(prefixRecordChangeKeySpace, encodeUint64(afterRecordVersion+1)),
		pebbleutil.PrefixToUpperBound(encodeSimpleKey(prefixRecordChangeKeySpace, nil))
}

func (ks recordChangeKeySpaceType) decodeValue(data []byte) (*databrokerpb.Record, error) {
	return decodeProto[databrokerpb.Record](data)
}

func (ks recordChangeKeySpaceType) delete(w writer, version uint64) error {
	return pebbleDelete(w, ks.encodeKey(version))
}

func (recordChangeKeySpaceType) deleteAll(w writer) error {
	return pebbleDeletePrefix(w, []byte{prefixRecordChangeKeySpace})
}

func (ks recordChangeKeySpaceType) encodeKey(version uint64) []byte {
	return encodeSimpleKey(prefixRecordChangeKeySpace, encodeUint64(version))
}

func (ks recordChangeKeySpaceType) encodeValue(record *databrokerpb.Record) []byte {
	return encodeProto(record)
}

func (ks recordChangeKeySpaceType) get(r reader, version uint64) (*databrokerpb.Record, error) {
	return pebbleGet(r, ks.encodeKey(version), ks.decodeValue)
}

func (ks recordChangeKeySpaceType) getFirstVersion(r reader) (uint64, error) {
	opts := new(pebble.IterOptions)
	opts.LowerBound, opts.UpperBound = ks.bounds(0)

	it, err := r.NewIter(opts)
	if err != nil {
		return 0, err
	}

	if !it.First() {
		return 0, it.Close()
	}

	record, err := ks.decodeValue(it.Value())
	if err != nil {
		_ = it.Close()
		return 0, err
	}

	return record.GetVersion(), it.Close()
}

func (ks recordChangeKeySpaceType) getLastVersion(r reader) (uint64, error) {
	opts := new(pebble.IterOptions)
	opts.LowerBound, opts.UpperBound = ks.bounds(0)

	it, err := r.NewIter(opts)
	if err != nil {
		return 0, err
	}

	if !it.Last() {
		return 0, it.Close()
	}

	record, err := ks.decodeValue(it.Value())
	if err != nil {
		_ = it.Close()
		return 0, err
	}

	return record.GetVersion(), it.Close()
}

func (ks recordChangeKeySpaceType) iterate(r reader, afterRecordVersion uint64) iter.Seq2[*databrokerpb.Record, error] {
	return func(yield func(*databrokerpb.Record, error) bool) {
		opts := new(pebble.IterOptions)
		opts.LowerBound, opts.UpperBound = ks.bounds(afterRecordVersion)
		for value, err := range pebbleutil.IterateValues(r, opts) {
			if err != nil {
				yield(nil, err)
				return
			}

			record, err := ks.decodeValue(value)
			if err != nil {
				continue
			}
			if !yield(record, nil) {
				return
			}
		}
	}
}

func (ks recordChangeKeySpaceType) set(w writer, record *databrokerpb.Record) error {
	return pebbleSet(w, ks.encodeKey(record.GetVersion()), ks.encodeValue(record))
}

// record-change-index-by-type:
//	keys: prefix-record-change-index-by-type | {recordType as bytes} | 0x00 | {version as uint64}
//	values: empty

type recordChangeIndexByTypeKeySpaceType struct{}

var recordChangeIndexByTypeKeySpace recordChangeIndexByTypeKeySpaceType

func (ks recordChangeIndexByTypeKeySpaceType) bounds(recordType string, afterRecordVersion uint64) ([]byte, []byte) {
	return encodeJoinedKey(prefixRecordChangeIndexByTypeKeySpace, []byte(recordType), encodeUint64(afterRecordVersion+1)),
		pebbleutil.PrefixToUpperBound(encodeJoinedKey(prefixRecordChangeIndexByTypeKeySpace, []byte(recordType)))
}

func (ks recordChangeIndexByTypeKeySpaceType) decodeKey(data []byte) (recordType string, version uint64, err error) {
	segments, err := decodeJoinedKey(data, prefixRecordChangeIndexByTypeKeySpace, 2)
	if err != nil {
		return "", 0, err
	}

	recordType = string(segments[0])
	version, err = decodeUint64(segments[1])
	if err != nil {
		return "", 0, err
	}

	return recordType, version, nil
}

func (ks recordChangeIndexByTypeKeySpaceType) encodeKey(recordType string, version uint64) []byte {
	return encodeJoinedKey(prefixRecordChangeIndexByTypeKeySpace,
		[]byte(recordType),
		encodeUint64(version))
}

func (ks recordChangeIndexByTypeKeySpaceType) delete(w writer, recordType string, version uint64) error {
	return pebbleDelete(w, ks.encodeKey(recordType, version))
}

func (recordChangeIndexByTypeKeySpaceType) deleteAll(w writer) error {
	return pebbleDeletePrefix(w, []byte{prefixRecordChangeIndexByTypeKeySpace})
}

func (ks recordChangeIndexByTypeKeySpaceType) iterate(r reader, recordType string, afterRecordVersion uint64) iter.Seq2[*databrokerpb.Record, error] {
	return func(yield func(*databrokerpb.Record, error) bool) {
		opts := new(pebble.IterOptions)
		opts.LowerBound, opts.UpperBound = ks.bounds(recordType, afterRecordVersion)
		for key, err := range pebbleutil.IterateKeys(r, opts) {
			if err != nil {
				yield(nil, err)
				return
			}

			_, version, err := ks.decodeKey(key)
			if err != nil {
				continue
			}

			record, err := recordChangeKeySpace.get(r, version)
			if err != nil {
				continue
			}

			if !yield(record, nil) {
				return
			}
		}
	}
}

func (ks recordChangeIndexByTypeKeySpaceType) set(w writer, recordType string, version uint64) error {
	return pebbleSet(w, ks.encodeKey(recordType, version), nil)
}

// registry-service:
//	keys: prefix-registry-service | {kind as uint64} | 0x00 | {endpoint as bytes}
//	values: {expiresAt as timestamp}

type registryServiceKeySpaceType struct{}

var registryServiceKeySpace registryServiceKeySpaceType

func (ks registryServiceKeySpaceType) bounds() (lowerBound []byte, upperBound []byte) {
	prefix := []byte{prefixRegistryServiceKeySpace}
	return prefix, pebbleutil.PrefixToUpperBound(prefix)
}

func (ks registryServiceKeySpaceType) decodeKey(data []byte) (kind registrypb.ServiceKind, endpoint string, err error) {
	if !bytes.HasPrefix(data, []byte{prefixRegistryServiceKeySpace}) {
		return 0, "", fmt.Errorf("invalid key, missing registry service prefix")
	}
	data = data[1:]
	if len(data) < 1 {
		return 0, "", fmt.Errorf("invalid key, expected kind")
	}
	kind = registrypb.ServiceKind(data[0])

	data = data[1:]
	endpoint = string(data)
	return kind, endpoint, nil
}

func (ks registryServiceKeySpaceType) decodeValue(data []byte) (time.Time, error) {
	return decodeTimestamp(data)
}

func (ks registryServiceKeySpaceType) encodeKey(kind registrypb.ServiceKind, endpoint string) []byte {
	return encodeSimpleKey(prefixRegistryServiceKeySpace, append([]byte{byte(kind)}, endpoint...))
}

func (ks registryServiceKeySpaceType) encodeValue(expiresAt time.Time) []byte {
	return encodeTimestamp(expiresAt)
}

func (ks registryServiceKeySpaceType) delete(w writer, kind registrypb.ServiceKind, endpoint string) error {
	return pebbleDelete(w, ks.encodeKey(kind, endpoint))
}

func (ks registryServiceKeySpaceType) iterate(r reader) iter.Seq2[registryServiceNode, error] {
	return func(yield func(registryServiceNode, error) bool) {
		opts := &pebble.IterOptions{}
		opts.LowerBound, opts.UpperBound = ks.bounds()

		for node, err := range pebbleutil.Iterate(r, opts, func(it *pebble.Iterator) (node registryServiceNode, err error) {
			node.kind, node.endpoint, err = ks.decodeKey(it.Key())
			if err != nil {
				return node, err
			}
			node.expiresAt, err = ks.decodeValue(it.Value())
			if err != nil {
				return node, err
			}
			return node, nil
		}) {
			if !yield(node, err) {
				return
			}
		}
	}
}

func (ks registryServiceKeySpaceType) set(w writer, node registryServiceNode) error {
	return pebbleSet(w, ks.encodeKey(node.kind, node.endpoint), ks.encodeValue(node.expiresAt))
}
