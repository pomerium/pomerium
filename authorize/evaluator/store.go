package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/square/go-jose.v2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// A Store stores data for the OPA rego policy evaluation.
type Store struct {
	opaStore storage.Store

	mu             sync.RWMutex
	dataBrokerData map[string]map[string]proto.Message
}

// NewStore creates a new Store.
func NewStore() *Store {
	return &Store{
		opaStore:       inmem.New(),
		dataBrokerData: make(map[string]map[string]proto.Message),
	}
}

// NewStoreFromProtos creates a new Store from an existing set of protobuf messages.
func NewStoreFromProtos(serverVersion uint64, msgs ...proto.Message) *Store {
	s := NewStore()
	for _, msg := range msgs {
		any, err := anypb.New(msg)
		if err != nil {
			continue
		}

		record := new(databroker.Record)
		record.ModifiedAt = timestamppb.Now()
		record.Version = cryptutil.NewRandomUInt64()
		record.Id = uuid.New().String()
		record.Data = any
		record.Type = any.TypeUrl
		if hasID, ok := msg.(interface{ GetId() string }); ok {
			record.Id = hasID.GetId()
		}

		s.UpdateRecord(serverVersion, record)
	}
	return s
}

// ClearRecords removes all the records from the store.
func (s *Store) ClearRecords() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.dataBrokerData = make(map[string]map[string]proto.Message)
}

// GetRecordData gets a record's data from the store. `nil` is returned
// if no record exists for the given type and id.
func (s *Store) GetRecordData(typeURL, id string) proto.Message {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, ok := s.dataBrokerData[typeURL]
	if !ok {
		return nil
	}

	return m[id]
}

// UpdateIssuer updates the issuer in the store. The issuer is used as part of JWT construction.
func (s *Store) UpdateIssuer(issuer string) {
	s.write("/issuer", issuer)
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
func (s *Store) UpdateRoutePolicies(routePolicies []config.Policy) {
	s.write("/route_policies", routePolicies)
}

// UpdateRecord updates a record in the store.
func (s *Store) UpdateRecord(serverVersion uint64, record *databroker.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, ok := s.dataBrokerData[record.GetType()]
	if !ok {
		m = make(map[string]proto.Message)
		s.dataBrokerData[record.GetType()] = m
	}
	if record.GetDeletedAt() != nil {
		delete(m, record.GetId())
	} else {
		m[record.GetId()], _ = record.GetData().UnmarshalNew()
	}
}

// UpdateSigningKey updates the signing key stored in the database. Signing operations
// in rego use JWKs, so we take in that format.
func (s *Store) UpdateSigningKey(signingKey *jose.JSONWebKey) {
	s.write("/signing_key", signingKey)
}

func (s *Store) write(rawPath string, value interface{}) {
	err := storage.Txn(context.Background(), s.opaStore, storage.WriteParams, func(txn storage.Transaction) error {
		return s.writeTxn(txn, rawPath, value)
	})
	if err != nil {
		log.Error().Err(err).Msg("opa-store: error writing data")
		return
	}
}

func (s *Store) writeTxn(txn storage.Transaction, rawPath string, value interface{}) error {
	p, ok := storage.ParsePath(rawPath)
	if !ok {
		return fmt.Errorf("invalid path")
	}

	if len(p) > 1 {
		err := storage.MakeDir(context.Background(), s.opaStore, txn, p[:len(p)-1])
		if err != nil {
			return err
		}
	}

	var op storage.PatchOp = storage.ReplaceOp
	_, err := s.opaStore.Read(context.Background(), txn, p)
	if storage.IsNotFound(err) {
		op = storage.AddOp
	} else if err != nil {
		return err
	}

	return s.opaStore.Write(context.Background(), txn, op, p, value)
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
		recordType, ok := op1.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("invalid record type: %T", op1)
		}

		recordID, ok := op2.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("invalid record id: %T", op2)
		}

		msg := s.GetRecordData(string(recordType), string(recordID))
		if msg == nil {
			return ast.NullTerm(), nil
		}
		obj := toMap(msg)

		value, err := ast.InterfaceToValue(obj)
		if err != nil {
			return nil, err
		}

		return ast.NewTerm(value), nil
	})
}

func toMap(msg proto.Message) map[string]interface{} {
	bs, _ := json.Marshal(msg)
	var obj map[string]interface{}
	_ = json.Unmarshal(bs, &obj)
	return obj
}
