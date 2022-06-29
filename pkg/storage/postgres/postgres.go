// Package postgres contains an implementation of the storage.Backend backed by postgres.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/storage"
)

var (
	schemaName              = "pomerium"
	migrationInfoTableName  = "migration_info"
	recordsTableName        = "records"
	recordChangesTableName  = "record_changes"
	recordChangeNotifyName  = "pomerium_record_change"
	recordOptionsTableName  = "record_options"
	leasesTableName         = "leases"
	serviceChangeNotifyName = "pomerium_service_change"
	servicesTableName       = "services"
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

func deleteExpiredServices(ctx context.Context, q querier, cutoff time.Time) (rowCount int64, err error) {
	cmd, err := q.Exec(ctx, `
		DELETE FROM `+schemaName+`.`+servicesTableName+`
		WHERE expires_at < $1
	`, cutoff)
	if err != nil {
		return 0, err
	}
	return cmd.RowsAffected(), nil
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

func getNextChangedRecord(ctx context.Context, q querier, recordType string, afterRecordVersion uint64) (*databroker.Record, error) {
	var recordID string
	var version uint64
	var data pgtype.JSONB
	var modifiedAt pgtype.Timestamptz
	var deletedAt pgtype.Timestamptz
	query := `
		SELECT type, id, version, data, modified_at, deleted_at
		FROM ` + schemaName + `.` + recordChangesTableName + `
		WHERE version > $1
	`
	args := []any{afterRecordVersion}
	if recordType != "" {
		query += ` AND type = $2`
		args = append(args, recordType)
	}
	query += `
		ORDER BY version ASC
		LIMIT 1
	`
	err := q.QueryRow(ctx, query, args...).Scan(&recordType, &recordID, &version, &data, &modifiedAt, &deletedAt)
	if isNotFound(err) {
		return nil, storage.ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("error querying next changed record: %w", err)
	}

	var any anypb.Any
	err = protojson.Unmarshal(data.Bytes, &any)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling changed record data: %w", err)
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

func listServices(ctx context.Context, q querier) ([]*registry.Service, error) {
	var services []*registry.Service

	query := `
		SELECT kind, endpoint
		FROM  ` + schemaName + `.` + servicesTableName + `
		ORDER BY kind, endpoint
	`
	rows, err := q.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var kind, endpoint string
		err = rows.Scan(&kind, &endpoint)
		if err != nil {
			return nil, err
		}

		services = append(services, &registry.Service{
			Kind:     registry.ServiceKind(registry.ServiceKind_value[kind]),
			Endpoint: endpoint,
		})
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return services, nil
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

func putRecordAndChange(ctx context.Context, q querier, record *databroker.Record) error {
	data, err := jsonbFromAny(record.GetData())
	if err != nil {
		return err
	}

	modifiedAt := timestamptzFromTimestamppb(record.GetModifiedAt())
	deletedAt := timestamptzFromTimestamppb(record.GetDeletedAt())
	indexCIDR := &pgtype.Text{Status: pgtype.Null}
	if cidr := storage.GetRecordIndexCIDR(record.GetData()); cidr != nil {
		_ = indexCIDR.Set(cidr.String())
	}

	query := `
		WITH t1 AS (
			INSERT INTO ` + schemaName + `.` + recordChangesTableName + ` (type, id, data, modified_at, deleted_at)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING *
		)
	`
	args := []any{
		record.GetType(), record.GetId(), data, modifiedAt, deletedAt,
	}
	if record.GetDeletedAt() == nil {
		query += `
			INSERT INTO ` + schemaName + `.` + recordsTableName + ` (type, id, version, data, modified_at, index_cidr)
			VALUES ($1, $2, (SELECT version FROM t1), $3, $4, $6)
			ON CONFLICT (type, id) DO UPDATE
			SET version=(SELECT version FROM t1), data=$3, modified_at=$4, index_cidr=$6
			RETURNING ` + schemaName + `.` + recordsTableName + `.version
		`
		args = append(args, indexCIDR)
	} else {
		query += `
			DELETE FROM ` + schemaName + `.` + recordsTableName + `
			WHERE type=$1 AND id=$2
			RETURNING ` + schemaName + `.` + recordsTableName + `.version
		`
	}
	err = q.QueryRow(ctx, query, args...).Scan(&record.Version)
	if err != nil && !isNotFound(err) {
		return err
	}

	return nil
}

func putService(ctx context.Context, q querier, svc *registry.Service, expiresAt time.Time) error {
	query := `
		INSERT INTO ` + schemaName + `.` + servicesTableName + ` (kind, endpoint, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (kind, endpoint) DO UPDATE
		SET expires_at=$3
	`
	_, err := q.Exec(ctx, query, svc.GetKind().String(), svc.GetEndpoint(), expiresAt)
	return err
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

func signalServiceChange(ctx context.Context, q querier) error {
	_, err := q.Exec(ctx, `NOTIFY `+serviceChangeNotifyName)
	return err
}

func jsonbFromAny(any *anypb.Any) (pgtype.JSONB, error) {
	if any == nil {
		return pgtype.JSONB{Status: pgtype.Null}, nil
	}

	bs, err := protojson.Marshal(any)
	if err != nil {
		return pgtype.JSONB{Status: pgtype.Null}, err
	}

	return pgtype.JSONB{Bytes: bs, Status: pgtype.Present}, nil
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
