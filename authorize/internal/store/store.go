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
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
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

		var regoValue ast.Value
		switch msg := msg.(type) {
		case *session.Session:
			regoValue = sessionToRegoValue(msg)
		case *user.User:
			regoValue = userToRegoValue(msg)
		default:
			regoValue, err = ast.InterfaceToValue(toMap(msg))
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("authorize/store: error converting object to rego")
				return ast.NullTerm(), nil
			}
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

func userToRegoValue(u *user.User) ast.Value {
	deviceCredentialIds := []*ast.Term{}
	for _, id := range u.DeviceCredentialIds {
		deviceCredentialIds = append(deviceCredentialIds, ast.StringTerm(id))
	}
	return ast.NewObject(
		ast.Item(ast.StringTerm("version"), ast.StringTerm(u.Version)),
		ast.Item(ast.StringTerm("id"), ast.StringTerm(u.Id)),
		ast.Item(ast.StringTerm("name"), ast.StringTerm(u.Name)),
		ast.Item(ast.StringTerm("email"), ast.StringTerm(u.Email)),
		ast.Item(ast.StringTerm("claims"), claimsValue(u.Claims)),
		ast.Item(ast.StringTerm("device_credential_ids"), ast.ArrayTerm(deviceCredentialIds...)),
	)
}

func sessionToRegoValue(s *session.Session) ast.Value {
	audience := []*ast.Term{}
	for _, aud := range s.Audience {
		audience = append(audience, ast.StringTerm(aud))
	}
	deviceCredentials := []*ast.Term{}
	for _, dc := range s.DeviceCredentials {
		terms := [][2]*ast.Term{
			ast.Item(ast.StringTerm("type_id"), ast.StringTerm(dc.TypeId)),
		}
		switch cred := dc.Credential.(type) {
		case *session.Session_DeviceCredential_Id:
			terms = append(terms, ast.Item(ast.StringTerm("id"), ast.StringTerm(cred.Id)))
		case *session.Session_DeviceCredential_Unavailable:
			terms = append(terms, ast.Item(ast.StringTerm("unavailable"), ast.ObjectTerm()))
		}
		deviceCredentials = append(deviceCredentials, ast.ObjectTerm(terms...))
	}
	return ast.NewObject(
		ast.Item(ast.StringTerm("version"), ast.StringTerm(s.Version)),
		ast.Item(ast.StringTerm("id"), ast.StringTerm(s.Id)),
		ast.Item(ast.StringTerm("user_id"), ast.StringTerm(s.UserId)),
		ast.Item(ast.StringTerm("device_credentials"), ast.ArrayTerm(deviceCredentials...)),
		ast.Item(ast.StringTerm("expires_at"), timestampValue(s.ExpiresAt)),
		ast.Item(ast.StringTerm("issued_at"), timestampValue(s.IssuedAt)),
		ast.Item(ast.StringTerm("accessed_at"), timestampValue(s.AccessedAt)),
		ast.Item(ast.StringTerm("id_token"), ast.ObjectTerm(
			ast.Item(ast.StringTerm("issuer"), ast.StringTerm(s.IdToken.Issuer)),
			ast.Item(ast.StringTerm("subject"), ast.StringTerm(s.IdToken.Subject)),
			ast.Item(ast.StringTerm("expires_at"), timestampValue(s.IdToken.ExpiresAt)),
			ast.Item(ast.StringTerm("issued_at"), timestampValue(s.IdToken.IssuedAt)),
			ast.Item(ast.StringTerm("raw"), ast.StringTerm(s.IdToken.Raw)),
		)),
		ast.Item(ast.StringTerm("oauth_token"), ast.ObjectTerm(
			ast.Item(ast.StringTerm("access_token"), ast.StringTerm(s.OauthToken.AccessToken)),
			ast.Item(ast.StringTerm("token_type"), ast.StringTerm(s.OauthToken.TokenType)),
			ast.Item(ast.StringTerm("expires_at"), timestampValue(s.OauthToken.ExpiresAt)),
			ast.Item(ast.StringTerm("refresh_token"), ast.StringTerm(s.OauthToken.RefreshToken)),
		)),
		ast.Item(ast.StringTerm("claims"), claimsValue(s.Claims)),
		ast.Item(ast.StringTerm("audience"), ast.ArrayTerm(audience...)),
	)
}

func timestampValue(t *timestamppb.Timestamp) *ast.Term {
	if t == nil {
		return ast.NullTerm()
	}
	return ast.ObjectTerm(
		ast.Item(ast.StringTerm("nanos"), ast.IntNumberTerm(int(t.Nanos))),
		ast.Item(ast.StringTerm("seconds"), &ast.Term{Value: ast.MustInterfaceToValue(t.Seconds)}),
	)
}

func claimsValue(claims map[string]*structpb.ListValue) *ast.Term {
	obj := [][2]*ast.Term{}
	for key, values := range claims {
		keyTerm := ast.StringTerm(key)
		arr := []*ast.Term{}
		for _, x := range values.Values {
			switch v := x.GetKind().(type) {
			case *structpb.Value_NumberValue:
				if v != nil {
					arr = append(arr, ast.FloatNumberTerm(v.NumberValue))
				}
			case *structpb.Value_StringValue:
				if v != nil {
					arr = append(arr, ast.StringTerm(v.StringValue))
				}
			case *structpb.Value_BoolValue:
				if v != nil {
					arr = append(arr, ast.BooleanTerm(v.BoolValue))
				}
			case *structpb.Value_StructValue:
				if v != nil {
					arr = append(arr, ast.NewTerm(ast.MustInterfaceToValue(v.StructValue.AsMap())))
				}
			case *structpb.Value_ListValue:
				if v != nil {
					arr = append(arr, ast.NewTerm(ast.MustInterfaceToValue(v.ListValue.AsSlice())))
				}
			}
		}
		obj = append(obj, ast.Item(keyTerm, &ast.Term{Value: ast.NewArray(arr...)}))
	}
	return ast.ObjectTerm(obj...)
}
