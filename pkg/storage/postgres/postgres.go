// Package postgres contains an implementation of the storage.Backend backed by postgres.
package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

var (
	schemaName             = "pomerium"
	migrationInfoTableName = "migration_info"
	recordsTableName       = "records"
	recordChangesTableName = "record_changes"
	recordChangeNotifyName = "pomerium_record_change"
	recordOptionsTableName = "record_options"
	leasesTableName        = "leases"
)

type querier interface {
	Exec(ctx context.Context, sql string, arguments ...interface{}) (commandTag pgconn.CommandTag, err error)
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}

func deleteChangesBefore(ctx context.Context, q querier, cutoff time.Time) error {
	_, err := q.Exec(ctx, `
		DELETE FROM `+schemaName+`.`+recordChangesTableName+`
		WHERE modified_at < $1
	`, cutoff)
	return err
}

func dup(record *databroker.Record) *databroker.Record {
	return proto.Clone(record).(*databroker.Record)
}

func enforceOptions(ctx context.Context, q querier, recordType string, options *databroker.Options) error {
	if options == nil || options.Capacity == nil {
		return nil
	}

	_, err := q.Exec(ctx, `
		DELETE FROM `+schemaName+`.`+recordsTableName+`
		WHERE type=$1
		  AND id NOT IN (
			SELECT id
			FROM `+schemaName+`.`+recordsTableName+`
			WHERE type=$1
			ORDER BY version DESC
			LIMIT $2
		)
	`, recordType, options.GetCapacity())
	return err
}

func getLatestRecordVersion(ctx context.Context, q querier) (recordVersion uint64, err error) {
	err = q.QueryRow(ctx, `
		SELECT version
		FROM `+schemaName+`.`+recordChangesTableName+`
		ORDER BY version DESC
		LIMIT 1
	`).Scan(&recordVersion)
	if isNotFound(err) {
		err = nil
	}
	return recordVersion, err
}

func getNextChangedRecord(ctx context.Context, q querier, afterRecordVersion uint64) (*databroker.Record, error) {
	var recordType, recordID string
	var version uint64
	var data pgtype.JSONB
	var modifiedAt pgtype.Timestamptz
	var deletedAt pgtype.Timestamptz
	err := q.QueryRow(ctx, `
		SELECT type, id, version, data, modified_at, deleted_at
		  FROM `+schemaName+`.`+recordChangesTableName+`
		 WHERE version > $1
	`, afterRecordVersion).Scan(&recordType, &recordID, &version, &data, &modifiedAt, &deletedAt)
	if isNotFound(err) {
		return nil, storage.ErrNotFound
	} else if err != nil {
		return nil, err
	}

	var any anypb.Any
	err = protojson.Unmarshal(data.Bytes, &any)
	if err != nil {
		return nil, err
	}

	return &databroker.Record{
		Version:    version,
		Type:       recordType,
		Id:         recordID,
		Data:       &any,
		ModifiedAt: timestamppbFromTimestamptz(modifiedAt),
		DeletedAt:  timestamppbFromTimestamptz(deletedAt),
	}, nil
}

func getOptions(ctx context.Context, q querier, recordType string) (*databroker.Options, error) {
	var capacity pgtype.Int8
	err := q.QueryRow(ctx, `
		SELECT capacity
		FROM `+schemaName+`.`+recordOptionsTableName+`
		WHERE type=$1
	`, recordType).Scan(&capacity)
	if err != nil && !isNotFound(err) {
		return nil, err
	}
	options := new(databroker.Options)
	if capacity.Status == pgtype.Present {
		options.Capacity = proto.Uint64(uint64(capacity.Int))
	}
	return options, nil
}

func getRecord(ctx context.Context, q querier, recordType, recordID string) (*databroker.Record, error) {
	var version uint64
	var data pgtype.JSONB
	var modifiedAt pgtype.Timestamptz
	err := q.QueryRow(ctx, `
		SELECT version, data, modified_at
		  FROM `+schemaName+`.`+recordsTableName+`
		 WHERE type=$1 AND id=$2
	`, recordType, recordID).Scan(&version, &data, &modifiedAt)
	if isNotFound(err) {
		return nil, storage.ErrNotFound
	} else if err != nil {
		return nil, err
	}

	var any anypb.Any
	err = protojson.Unmarshal(data.Bytes, &any)
	if err != nil {
		return nil, err
	}

	return &databroker.Record{
		Version:    version,
		Type:       recordType,
		Id:         recordID,
		Data:       &any,
		ModifiedAt: timestamppbFromTimestamptz(modifiedAt),
	}, nil
}

func listRecords(ctx context.Context, q querier, expr storage.FilterExpression, offset, limit int) ([]*databroker.Record, error) {
	args := []interface{}{offset, limit}
	query := `
		SELECT type, id, version, data, modified_at
		FROM ` + schemaName + `.` + recordsTableName + `
	`
	if expr != nil {
		query += "WHERE "
		err := addFilterExpressionToQuery(&query, &args, expr)
		if err != nil {
			return nil, err
		}
	}
	query += `
		ORDER BY type, id
		LIMIT $2
		OFFSET $1
	`
	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*databroker.Record
	for rows.Next() {
		var recordType, id string
		var version uint64
		var data pgtype.JSONB
		var modifiedAt pgtype.Timestamptz
		err = rows.Scan(&recordType, &id, &version, &data, &modifiedAt)
		if err != nil {
			return nil, err
		}

		var any anypb.Any
		err = protojson.Unmarshal(data.Bytes, &any)
		if err != nil {
			return nil, err
		}

		records = append(records, &databroker.Record{
			Version:    version,
			Type:       recordType,
			Id:         id,
			Data:       &any,
			ModifiedAt: timestamppbFromTimestamptz(modifiedAt),
		})
	}
	return records, rows.Err()
}

func maybeAcquireLease(ctx context.Context, q querier, leaseName, leaseID string, ttl time.Duration) (leaseHolderID string, err error) {
	tbl := schemaName + "." + leasesTableName
	expiresAt := timestamptzFromTimestamppb(timestamppb.New(time.Now().Add(ttl)))
	now := timestamptzFromTimestamppb(timestamppb.Now())
	err = q.QueryRow(ctx, `
		INSERT INTO `+tbl+` (name, id, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (name) DO UPDATE
		SET id=CASE WHEN `+tbl+`.expires_at<$4 OR `+tbl+`.id=$2 THEN $2 ELSE `+tbl+`.id END,
		    expires_at=CASE WHEN `+tbl+`.expires_at<$4 OR `+tbl+`.id=$2 THEN $3 ELSE `+tbl+`.expires_at END
		RETURNING `+tbl+`.id
	`, leaseName, leaseID, expiresAt, now).Scan(&leaseHolderID)
	return leaseHolderID, err
}

func putRecordChange(ctx context.Context, q querier, record *databroker.Record) error {
	data := jsonbFromAny(record.GetData())
	modifiedAt := timestamptzFromTimestamppb(record.GetModifiedAt())
	deletedAt := timestamptzFromTimestamppb(record.GetDeletedAt())
	_, err := q.Exec(ctx, `
		INSERT INTO `+schemaName+`.`+recordChangesTableName+` (type, id, version, data, modified_at, deleted_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, record.GetType(), record.GetId(), record.GetVersion(), data, modifiedAt, deletedAt)
	if err != nil {
		return err
	}

	return nil
}

func putRecord(ctx context.Context, q querier, record *databroker.Record) error {
	data := jsonbFromAny(record.GetData())
	modifiedAt := timestamptzFromTimestamppb(record.GetModifiedAt())
	var err error
	if record.GetDeletedAt() == nil {
		_, err = q.Exec(ctx, `
			INSERT INTO `+schemaName+`.`+recordsTableName+` (type, id, version, data, modified_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (type, id) DO UPDATE
			SET version=$3, data=$4, modified_at=$5
		`, record.GetType(), record.GetId(), record.GetVersion(), data, modifiedAt)
	} else {
		_, err = q.Exec(ctx, `
			DELETE FROM `+schemaName+`.`+recordsTableName+`
			WHERE type=$1 AND id=$2 AND version<$3
		`, record.GetType(), record.GetId(), record.GetVersion())
	}
	if err != nil {
		return err
	}
	return nil
}

func setOptions(ctx context.Context, q querier, recordType string, options *databroker.Options) error {
	capacity := pgtype.Int8{Status: pgtype.Null}
	if options != nil && options.Capacity != nil {
		capacity.Int = int64(options.GetCapacity())
		capacity.Status = pgtype.Present
	}

	_, err := q.Exec(ctx, `
		INSERT INTO `+schemaName+`.`+recordOptionsTableName+` (type, capacity)
		VALUES ($1, $2)
		ON CONFLICT (type) DO UPDATE
		SET capacity=$2
	`, recordType, capacity)
	return err
}

func signalRecordChange(ctx context.Context, q querier) error {
	_, err := q.Exec(ctx, `NOTIFY `+recordChangeNotifyName)
	return err
}

func jsonbFromAny(any *anypb.Any) pgtype.JSONB {
	if any == nil {
		return pgtype.JSONB{Status: pgtype.Null}
	}

	bs, err := protojson.Marshal(any)
	if err != nil {
		log.Warn(context.Background()).
			Err(err).
			Str("data", prototext.Format(any)).
			Msg("storage/postgres: error marshaling any to JSON")
		return pgtype.JSONB{Status: pgtype.Null}
	}

	return pgtype.JSONB{Bytes: bs, Status: pgtype.Present}
}

func timestamppbFromTimestamptz(ts pgtype.Timestamptz) *timestamppb.Timestamp {
	if ts.Status != pgtype.Present {
		return nil
	}
	return timestamppb.New(ts.Time)
}

func timestamptzFromTimestamppb(ts *timestamppb.Timestamp) pgtype.Timestamptz {
	if !ts.IsValid() {
		return pgtype.Timestamptz{Status: pgtype.Null}
	}
	return pgtype.Timestamptz{Time: ts.AsTime(), Status: pgtype.Present}
}

func isNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows) || errors.Is(err, storage.ErrNotFound)
}
