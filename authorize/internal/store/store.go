// Package store contains a datastore for authorization policy evaluation.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	opastorage "github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/types"
	octrace "go.opencensus.io/trace"
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
}

// New creates a new Store.
func New() *Store {
	return &Store{
		Store: inmem.New(),
	}
}

// UpdateGoogleCloudServerlessAuthenticationServiceAccount updates the google cloud serverless authentication
// service account in the store.
func (s *Store) UpdateGoogleCloudServerlessAuthenticationServiceAccount(serviceAccount string) {
	s.write("/google_cloud_serverless_authentication_service_account", serviceAccount)
}

// UpdateJWTClaimHeaders updates the jwt claim headers in the store.
func (s *Store) UpdateJWTClaimHeaders(jwtClaimHeaders map[string]string) {
	s.write("/jwt_claim_headers", jwtClaimHeaders)
}

// UpdateRoutePolicies updates the route policies in the store.
func (s *Store) UpdateRoutePolicies(routePolicies []*config.Policy) {
	s.write("/route_policies", routePolicies)
}

// UpdateSigningKey updates the signing key stored in the database. Signing operations
// in rego use JWKs, so we take in that format.
func (s *Store) UpdateSigningKey(signingKey *jose.JSONWebKey) {
	s.write("/signing_key", signingKey)
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
		ctx, span := trace.StartSpan(bctx.Context, "rego.get_databroker_record")
		defer span.End()

		recordType, ok := op1.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("invalid record type: %T", op1)
		}
		span.AddAttributes(octrace.StringAttribute("record_type", recordType.String()))

		value, ok := op2.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("invalid record id: %T", op2)
		}
		span.AddAttributes(octrace.StringAttribute("record_id", value.String()))

		req := &databroker.QueryRequest{
			Type:  string(recordType),
			Limit: 1,
		}
		req.SetFilterByIDOrIndex(string(value))

		res, err := storage.GetQuerier(ctx).Query(ctx, req)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("authorize/store: error retrieving record")
			return ast.NullTerm(), nil
		}

		if len(res.GetRecords()) == 0 {
			return ast.NullTerm(), nil
		}

		msg, _ := res.GetRecords()[0].GetData().UnmarshalNew()
		if msg == nil {
			return ast.NullTerm(), nil
		}

		// exclude expired records
		if hasExpiresAt, ok := msg.(interface{ GetExpiresAt() *timestamppb.Timestamp }); ok && hasExpiresAt.GetExpiresAt() != nil {
			if hasExpiresAt.GetExpiresAt().AsTime().Before(time.Now()) {
				return ast.NullTerm(), nil
			}
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

func toMap(msg proto.Message) map[string]any {
	bs, _ := json.Marshal(msg)
	var obj map[string]any
	_ = json.Unmarshal(bs, &obj)
	return obj
}
