// Package postgres contains an implementation of the storage.Backend backed by postgres.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

const (
	recordBatchSize   = 64
	watchPollInterval = 30 * time.Second
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
	Exec(ctx context.Context, sql string, arguments ...any) (commandTag pgconn.CommandTag, err error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func deleteChangesBefore(ctx context.Context, q querier, cutoff time.Time) error {
	_, err := q.Exec(ctx, `
		WITH t1 AS (
			SELECT version
			FROM `+schemaName+`.`+recordChangesTableName+`
			WHERE modified_at<$1
			FOR UPDATE SKIP LOCKED
		)
		DELETE FROM `+schemaName+`.`+recordChangesTableName+` t2
		USING t1
		WHERE t1.version=t2.version
	`, cutoff)
	return err
}

func deleteExpiredServices(ctx context.Context, q querier, cutoff time.Time) (rowCount int64, err error) {
	cmd, err := q.Exec(ctx, `
		WITH t1 AS (
			SELECT kind, endpoint
			FROM `+schemaName+`.`+servicesTableName+`
			WHERE expires_at<$1
			FOR UPDATE SKIP LOCKED
		)
		DELETE FROM `+schemaName+`.`+servicesTableName+` t2
		USING t1
		WHERE t1.kind=t2.kind
		  AND t1.endpoint=t2.endpoint
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
	if capacity.Valid {
		options.Capacity = proto.Uint64(uint64(capacity.Int64))
	}
	return options, nil
}

type lockMode string

const (
	lockModeNone   lockMode = ""
	lockModeUpdate lockMode = "FOR UPDATE"
)

func getRecord(
	ctx context.Context, q querier, recordType, recordID string, lockMode lockMode,
) (*databroker.Record, error) {
	var version uint64
	var data []byte
	var modifiedAt pgtype.Timestamptz
	err := q.QueryRow(ctx, `
		SELECT version, data, modified_at
		  FROM `+schemaName+`.`+recordsTableName+`
		 WHERE type=$1 AND id=$2 `+string(lockMode),
		recordType, recordID).Scan(&version, &data, &modifiedAt)
	if isNotFound(err) {
		return nil, storage.ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("postgres: failed to execute query: %w", err)
	}

	a, err := protoutil.UnmarshalAnyJSON(data)
	if isUnknownType(err) {
		return nil, storage.ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("postgres: failed to unmarshal data: %w", err)
	}

	return &databroker.Record{
		Version:    version,
		Type:       recordType,
		Id:         recordID,
		Data:       a,
		ModifiedAt: timestamppbFromTimestamptz(modifiedAt),
	}, nil
}

func listChangedRecordsAfter(ctx context.Context, q querier, recordType string, lastRecordVersion uint64) ([]*databroker.Record, error) {
	args := []any{lastRecordVersion, recordBatchSize}
	query := `
		SELECT type, id, version, data, modified_at, deleted_at
		FROM ` + schemaName + `.` + recordChangesTableName + `
		WHERE version>$1
	`
	if recordType != "" {
		args = append(args, recordType)
		query += ` AND type=$3`
	}
	query += `
		ORDER BY version
		LIMIT $2
	`
	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: failed to execute query: %w", err)
	}
	return pgx.CollectRows(rows, collectRecord)
}

func listLatestRecordsAfter(ctx context.Context, q querier, expr storage.FilterExpression, lastRecordType, lastRecordID string) ([]*databroker.Record, error) {
	args := []any{lastRecordType, lastRecordID, recordBatchSize}
	query := `
		SELECT type, id, version, data, modified_at, NULL::timestamptz
		FROM ` + schemaName + `.` + recordsTableName + `
		WHERE ((type>$1) OR (type=$1 AND id>$2))
	`
	if expr != nil {
		query += "AND "
		err := addFilterExpressionToQuery(&query, &args, expr)
		if err != nil {
			return nil, fmt.Errorf("postgres: failed to add filter to query: %w", err)
		}
	}
	query += `
		ORDER BY type, id
		LIMIT $3
	`
	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: failed to execute query: %w", err)
	}
	return pgx.CollectRows(rows, collectRecord)
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
		return nil, fmt.Errorf("postgres: failed to execute query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var kind, endpoint string
		err = rows.Scan(&kind, &endpoint)
		if err != nil {
			return nil, fmt.Errorf("postgres: failed to scan row: %w", err)
		}

		services = append(services, &registry.Service{
			Kind:     registry.ServiceKind(registry.ServiceKind_value[kind]),
			Endpoint: endpoint,
		})
	}
	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("postgres: error iterating over rows: %w", err)
	}

	return services, nil
}

func listTypes(ctx context.Context, q querier) ([]string, error) {
	query := `
		SELECT DISTINCT type
		FROM ` + schemaName + `.` + recordsTableName + `
	`
	rows, err := q.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("postgres: failed to execute query: %w", err)
	}
	defer rows.Close()

	var types []string
	for rows.Next() {
		var recordType string
		err = rows.Scan(&recordType)
		if err != nil {
			return nil, fmt.Errorf("postgres: failed to scan row: %w", err)
		}

		types = append(types, recordType)
	}
	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("postgres: error iterating over rows: %w", err)
	}

	sort.Strings(types)
	return types, nil
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
		return fmt.Errorf("postgres: failed to convert any to json: %w", err)
	}

	modifiedAt := timestamptzFromTimestamppb(record.GetModifiedAt())
	deletedAt := timestamptzFromTimestamppb(record.GetDeletedAt())
	indexCIDR := &pgtype.Text{Valid: false}
	if cidr := storage.GetRecordIndexCIDR(record.GetData()); cidr != nil {
		indexCIDR.String = cidr.String()
		indexCIDR.Valid = true
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
		return fmt.Errorf("postgres: failed to execute query: %w", err)
	}

	return nil
}

// patchRecord updates specific fields of an existing record.
func patchRecord(
	ctx context.Context, p *pgxpool.Pool, record *databroker.Record, fields *fieldmaskpb.FieldMask,
) error {
	tx, err := p.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, err := getRecord(ctx, tx, record.GetType(), record.GetId(), lockModeUpdate)
	if isNotFound(err) {
		return storage.ErrNotFound
	} else if err != nil {
		return err
	}

	if err := storage.PatchRecord(existing, record, fields); err != nil {
		return err
	}

	if err := putRecordAndChange(ctx, tx, record); err != nil {
		return err
	}

	return tx.Commit(ctx)
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
	capacity := pgtype.Int8{}
	if options != nil && options.Capacity != nil {
		capacity.Int64 = int64(options.GetCapacity())
		capacity.Valid = true
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

func jsonbFromAny(a *anypb.Any) ([]byte, error) {
	if a == nil {
		return nil, nil
	}

	return protojson.Marshal(a)
}

func timestamppbFromTimestamptz(ts pgtype.Timestamptz) *timestamppb.Timestamp {
	if !ts.Valid {
		return nil
	}
	return timestamppb.New(ts.Time)
}

func timestamptzFromTimestamppb(ts *timestamppb.Timestamp) pgtype.Timestamptz {
	if !ts.IsValid() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: ts.AsTime(), Valid: true}
}

func isNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows) || errors.Is(err, storage.ErrNotFound)
}

func isUnknownType(err error) bool {
	if err == nil {
		return false
	}

	return errors.Is(err, protoregistry.NotFound) ||
		strings.Contains(err.Error(), "unable to resolve") // protojson doesn't wrap errors so check for the string
}

func collectRecord(row pgx.CollectableRow) (*databroker.Record, error) {
	var recordType, id string
	var version uint64
	var data []byte
	var modifiedAt pgtype.Timestamptz
	var deletedAt pgtype.Timestamptz
	err := row.Scan(&recordType, &id, &version, &data, &modifiedAt, &deletedAt)
	if err != nil {
		return nil, fmt.Errorf("postgres: failed to scan row: %w", err)
	}

	a, err := protoutil.UnmarshalAnyJSON(data)
	if isUnknownType(err) || len(data) == 0 {
		a = protoutil.ToAny(protoutil.ToStruct(map[string]string{
			"id": id,
		}))
	} else if err != nil {
		return nil, fmt.Errorf("postgres: failed to unmarshal data: %w", err)
	}

	return &databroker.Record{
		Version:    version,
		Type:       recordType,
		Id:         id,
		Data:       a,
		ModifiedAt: timestamppbFromTimestamptz(modifiedAt),
		DeletedAt:  timestamppbFromTimestamptz(deletedAt),
	}, nil
}
