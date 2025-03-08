// Package store contains a datastore for authorization policy evaluation.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	opastorage "github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/types"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

// A Store stores data for the OPA rego policy evaluation.
type Store struct {
	opastorage.Store

	googleCloudServerlessAuthenticationServiceAccount atomic.Pointer[string]
	jwtClaimHeaders                                   atomic.Pointer[map[string]string]
	jwtGroupsFilter                                   atomic.Pointer[config.JWTGroupsFilter]
	defaultJWTIssuerFormat                            atomic.Pointer[config.JWTIssuerFormat]
	signingKey                                        atomic.Pointer[jose.JSONWebKey]
}

// New creates a new Store.
func New() *Store {
	return &Store{
		Store: inmem.New(),
	}
}

func (s *Store) GetGoogleCloudServerlessAuthenticationServiceAccount() string {
	v := s.googleCloudServerlessAuthenticationServiceAccount.Load()
	if v == nil {
		return ""
	}
	return *v
}

func (s *Store) GetJWTClaimHeaders() map[string]string {
	m := s.jwtClaimHeaders.Load()
	if m == nil {
		return nil
	}
	return *m
}

func (s *Store) GetJWTGroupsFilter() config.JWTGroupsFilter {
	if f := s.jwtGroupsFilter.Load(); f != nil {
		return *f
	}
	return config.JWTGroupsFilter{}
}

func (s *Store) GetDefaultJWTIssuerFormat() config.JWTIssuerFormat {
	if f := s.defaultJWTIssuerFormat.Load(); f != nil {
		return *f
	}
	return ""
}

func (s *Store) GetSigningKey() *jose.JSONWebKey {
	return s.signingKey.Load()
}

// UpdateGoogleCloudServerlessAuthenticationServiceAccount updates the google cloud serverless authentication
// service account in the store.
func (s *Store) UpdateGoogleCloudServerlessAuthenticationServiceAccount(serviceAccount string) {
	s.write("/google_cloud_serverless_authentication_service_account", serviceAccount)
	s.googleCloudServerlessAuthenticationServiceAccount.Store(&serviceAccount)
}

// UpdateJWTClaimHeaders updates the jwt claim headers in the store.
func (s *Store) UpdateJWTClaimHeaders(jwtClaimHeaders map[string]string) {
	s.write("/jwt_claim_headers", jwtClaimHeaders)
	s.jwtClaimHeaders.Store(&jwtClaimHeaders)
}

// UpdateJWTGroupsFilter updates the JWT groups filter in the store.
func (s *Store) UpdateJWTGroupsFilter(groups config.JWTGroupsFilter) {
	// This isn't used by the Rego code, so we don't need to write it to the opastorage.Store instance.
	s.jwtGroupsFilter.Store(&groups)
}

// UpdateDefaultJWTIssuerFormat updates the JWT groups filter in the store.
func (s *Store) UpdateDefaultJWTIssuerFormat(format config.JWTIssuerFormat) {
	// This isn't used by the Rego code, so we don't need to write it to the opastorage.Store instance.
	s.defaultJWTIssuerFormat.Store(&format)
}

// UpdateRoutePolicies updates the route policies in the store.
func (s *Store) UpdateRoutePolicies(routePolicies []*config.Policy) {
	s.write("/route_policies", routePolicies)
}

// UpdateSigningKey updates the signing key stored in the database. Signing operations
// in rego use JWKs, so we take in that format.
func (s *Store) UpdateSigningKey(signingKey *jose.JSONWebKey) {
	s.write("/signing_key", signingKey)
	s.signingKey.Store(signingKey)
}

func (s *Store) write(rawPath string, value any) {
	ctx := context.TODO()
	err := opastorage.Txn(ctx, s.Store, opastorage.WriteParams, func(txn opastorage.Transaction) error {
		return s.writeTxn(txn, rawPath, value)
	})
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("opa-store: error writing data")
		return
	}
}

func (s *Store) writeTxn(txn opastorage.Transaction, rawPath string, value any) error {
	p, ok := opastorage.ParsePath(rawPath)
	if !ok {
		return fmt.Errorf("invalid path")
	}

	if len(p) > 1 {
		err := opastorage.MakeDir(context.Background(), s, txn, p[:len(p)-1])
		if err != nil {
			return err
		}
	}

	var op opastorage.PatchOp = opastorage.ReplaceOp
	_, err := s.Read(context.Background(), txn, p)
	if opastorage.IsNotFound(err) {
		op = opastorage.AddOp
	} else if err != nil {
		return err
	}

	return s.Write(context.Background(), txn, op, p, value)
}

// GetDataBrokerRecordOption returns a function option that can retrieve databroker data.
func (s *Store) GetDataBrokerRecordOption() func(*rego.Rego) {
	return rego.Function2(&rego.Function{
		Name: "get_databroker_record",
		Decl: types.NewFunction(
			types.Args(types.S, types.S),
			types.NewObject(nil, types.NewDynamicProperty(types.S, types.S)),
		),
	}, func(bctx rego.BuiltinContext, op1 *ast.Term, op2 *ast.Term) (*ast.Term, error) {
		ctx, span := trace.Continue(bctx.Context, "rego.get_databroker_record")
		defer span.End()

		recordType, ok := op1.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("invalid record type: %T", op1)
		}
		span.SetAttributes(attribute.String("record_type", recordType.String()))

		recordIDOrIndex, ok := op2.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("invalid record id: %T", op2)
		}
		span.SetAttributes(attribute.String("record_id", recordIDOrIndex.String()))

		msg := s.GetDataBrokerRecord(ctx, string(recordType), string(recordIDOrIndex))
		if msg == nil {
			return ast.NullTerm(), nil
		}

		obj := toMap(msg)

		regoValue, err := ast.InterfaceToValue(obj)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("authorize/store: error converting object to rego")
			return ast.NullTerm(), nil
		}

		return ast.NewTerm(regoValue), nil
	})
}

func (s *Store) GetDataBrokerRecord(ctx context.Context, recordType, recordIDOrIndex string) proto.Message {
	req := &databroker.QueryRequest{
		Type:  recordType,
		Limit: 1,
	}
	req.SetFilterByIDOrIndex(recordIDOrIndex)

	res, err := storage.GetQuerier(ctx).Query(ctx, req, grpc.WaitForReady(true))
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authorize/store: error retrieving record")
		return nil
	}

	if len(res.GetRecords()) == 0 {
		return nil
	}

	msg, _ := res.GetRecords()[0].GetData().UnmarshalNew()
	if msg == nil {
		return nil
	}

	// exclude expired records
	if hasExpiresAt, ok := msg.(interface{ GetExpiresAt() *timestamppb.Timestamp }); ok && hasExpiresAt.GetExpiresAt() != nil {
		if hasExpiresAt.GetExpiresAt().AsTime().Before(time.Now()) {
			return nil
		}
	}

	return msg
}

func toMap(msg proto.Message) map[string]any {
	bs, _ := json.Marshal(msg)
	var obj map[string]any
	_ = json.Unmarshal(bs, &obj)
	return obj
}
