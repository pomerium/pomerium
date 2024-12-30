package evaluator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

// A headersEvaluatorEvaluation is a single evaluation of the headers evaluator.
type headersEvaluatorEvaluation struct {
	evaluator *HeadersEvaluator
	request   *HeadersRequest
	response  *HeadersResponse
	now       time.Time

	gotSessionOrServiceAccount bool
	cachedSession              *session.Session
	cachedServiceAccount       *user.ServiceAccount

	gotUser    bool
	cachedUser *user.User

	gotDirectoryUser    bool
	cachedDirectoryUser *structpb.Struct

	gotJWTPayloadJTI    bool
	cachedJWTPayloadJTI string

	gotJWTPayload    bool
	cachedJWTPayload map[string]any

	gotSignedJWT    bool
	cachedSignedJWT string
}

func newHeadersEvaluatorEvaluation(evaluator *HeadersEvaluator, request *HeadersRequest, now time.Time) *headersEvaluatorEvaluation {
	return &headersEvaluatorEvaluation{
		evaluator: evaluator,
		request:   request,
		response:  &HeadersResponse{Headers: make(http.Header)},
		now:       now,
	}
}

func (e *headersEvaluatorEvaluation) execute(ctx context.Context) (*HeadersResponse, error) {
	if err := e.fillHeaders(ctx); err != nil {
		return nil, err
	}
	return e.response, nil
}

func (e *headersEvaluatorEvaluation) fillJWTAssertionHeader(ctx context.Context) error {
	jwt, err := e.getSignedJWT(ctx)
	if err != nil {
		return err
	}
	e.response.Headers.Add("x-pomerium-jwt-assertion", jwt)
	return nil
}

func (e *headersEvaluatorEvaluation) fillJWTClaimHeaders(ctx context.Context) error {
	claims, err := e.getJWTPayload(ctx)
	if err != nil {
		return err
	}
	for headerName, claimKey := range e.evaluator.store.GetJWTClaimHeaders() {
		claim, ok := claims[claimKey]
		if !ok {
			e.response.Headers.Add(headerName, "")
			continue
		}
		e.response.Headers.Add(headerName, getHeaderStringValue(claim))
	}
	return nil
}

func (e *headersEvaluatorEvaluation) fillKubernetesHeaders(ctx context.Context) error {
	if e.request.KubernetesServiceAccountToken == "" {
		return nil
	}

	e.response.Headers.Add("Authorization", "Bearer "+e.request.KubernetesServiceAccountToken)
	impersonateUser, err := e.getJWTPayloadEmail(ctx)
	if err != nil {
		return err
	}
	if impersonateUser != "" {
		e.response.Headers.Add("Impersonate-User", impersonateUser)
	}
	impersonateGroups, err := e.getJWTPayloadGroups(ctx)
	if err != nil {
		return err
	}
	if len(impersonateGroups) > 0 {
		e.response.Headers.Add("Impersonate-Group", strings.Join(impersonateGroups, ","))
	}
	return nil
}

func (e *headersEvaluatorEvaluation) fillGoogleCloudServerlessHeaders(ctx context.Context) error {
	if e.request.EnableGoogleCloudServerlessAuthentication {
		h, err := getGoogleCloudServerlessHeaders(e.evaluator.store.GetGoogleCloudServerlessAuthenticationServiceAccount(), e.request.ToAudience)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("authorize/header-evaluator: error retrieving google cloud serverless headers")
			return err
		}
		for k, v := range h {
			e.response.Headers.Add(k, v)
		}
	}
	return nil
}

func (e *headersEvaluatorEvaluation) fillRoutingKeyHeaders() error {
	if e.request.EnableRoutingKey {
		e.response.Headers.Add("x-pomerium-routing-key", cryptoSHA256(e.request.Session.ID))
	}
	return nil
}

func (e *headersEvaluatorEvaluation) fillSetRequestHeaders(ctx context.Context) error {
	for k, v := range e.request.SetRequestHeaders {
		var retErr error
		e.response.Headers.Add(k, os.Expand(v, func(name string) string {
			switch name {
			case "$":
				return "$"
			case "pomerium.access_token":
				s, _, err := e.getSessionOrServiceAccount(ctx)
				if err != nil {
					retErr = err
					return ""
				}
				return s.GetOauthToken().GetAccessToken()
			case "pomerium.client_cert_fingerprint":
				return e.getClientCertFingerprint()
			case "pomerium.id_token":
				s, _, err := e.getSessionOrServiceAccount(ctx)
				if err != nil {
					retErr = err
					return ""
				}
				return s.GetIdToken().GetRaw()
			case "pomerium.jwt":
				jwt, err := e.getSignedJWT(ctx)
				if err != nil {
					retErr = err
					return ""
				}
				return jwt
			}

			return ""
		}))
		if retErr != nil {
			return retErr
		}
	}
	return nil
}

func (e *headersEvaluatorEvaluation) fillHeaders(ctx context.Context) error {
	if err := e.fillJWTAssertionHeader(ctx); err != nil {
		return err
	}
	if err := e.fillJWTClaimHeaders(ctx); err != nil {
		return err
	}
	if err := e.fillKubernetesHeaders(ctx); err != nil {
		return err
	}
	if err := e.fillGoogleCloudServerlessHeaders(ctx); err != nil {
		return err
	}
	if err := e.fillRoutingKeyHeaders(); err != nil {
		return err
	}
	if err := e.fillSetRequestHeaders(ctx); err != nil {
		return err
	}
	return nil
}

func (e *headersEvaluatorEvaluation) getSessionOrServiceAccount(ctx context.Context) (*session.Session, *user.ServiceAccount, error) {
	if e.gotSessionOrServiceAccount {
		return e.cachedSession, e.cachedServiceAccount, nil
	}

	if e.request.Session.ID != "" {
		msg, err := e.evaluator.store.GetDataBrokerRecord(ctx, "type.googleapis.com/user.ServiceAccount", e.request.Session.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("error looking up service account: %w", err)
		}
		e.cachedServiceAccount, _ = msg.(*user.ServiceAccount)
	}

	if e.request.Session.ID != "" && e.cachedServiceAccount == nil {
		msg, err := e.evaluator.store.GetDataBrokerRecord(ctx, "type.googleapis.com/session.Session", e.request.Session.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("error looking up session: %w", err)
		}
		e.cachedSession, _ = msg.(*session.Session)
	}
	if e.cachedSession != nil && e.cachedSession.GetImpersonateSessionId() != "" {
		msg, err := e.evaluator.store.GetDataBrokerRecord(ctx, "type.googleapis.com/session.Session", e.cachedSession.GetImpersonateSessionId())
		if err != nil {
			return nil, nil, fmt.Errorf("error looking up session: %w", err)
		}
		e.cachedSession, _ = msg.(*session.Session)
	}
	e.gotSessionOrServiceAccount = true
	return e.cachedSession, e.cachedServiceAccount, nil
}

func (e *headersEvaluatorEvaluation) getUser(ctx context.Context) (*user.User, error) {
	if e.gotUser {
		return e.cachedUser, nil
	}

	s, sa, err := e.getSessionOrServiceAccount(ctx)
	if err != nil {
		return nil, err
	}
	if sa != nil && sa.UserId != "" {
		msg, err := e.evaluator.store.GetDataBrokerRecord(ctx, "type.googleapis.com/user.User", sa.UserId)
		if err != nil {
			return nil, fmt.Errorf("error looking up user: %w", err)
		}
		e.cachedUser, _ = msg.(*user.User)
	} else if s != nil && s.UserId != "" {
		msg, err := e.evaluator.store.GetDataBrokerRecord(ctx, "type.googleapis.com/user.User", s.UserId)
		if err != nil {
			return nil, fmt.Errorf("error looking up user: %w", err)
		}
		e.cachedUser, _ = msg.(*user.User)
	}
	e.gotUser = true
	return e.cachedUser, nil
}

func (e *headersEvaluatorEvaluation) getClientCertFingerprint() string {
	cert, err := cryptutil.ParsePEMCertificate([]byte(e.request.ClientCertificate.Leaf))
	if err != nil {
		return ""
	}
	return cryptoSHA256(cert.Raw)
}

func (e *headersEvaluatorEvaluation) getDirectoryUser(ctx context.Context) (*structpb.Struct, error) {
	if e.gotDirectoryUser {
		return e.cachedDirectoryUser, nil
	}

	s, sa, err := e.getSessionOrServiceAccount(ctx)
	if err != nil {
		return nil, err
	}
	if sa != nil && sa.UserId != "" {
		msg, err := e.evaluator.store.GetDataBrokerRecord(ctx, directory.UserRecordType, sa.UserId)
		if err != nil {
			return nil, fmt.Errorf("error looking up directory user: %w", err)
		}
		e.cachedDirectoryUser, _ = msg.(*structpb.Struct)
	} else if s != nil && s.UserId != "" {
		msg, err := e.evaluator.store.GetDataBrokerRecord(ctx, directory.UserRecordType, s.UserId)
		if err != nil {
			return nil, fmt.Errorf("error looking up directory user: %w", err)
		}
		e.cachedDirectoryUser, _ = msg.(*structpb.Struct)
	}
	e.gotDirectoryUser = true
	return e.cachedDirectoryUser, nil
}

func (e *headersEvaluatorEvaluation) getGroupIDs(ctx context.Context) ([]string, error) {
	du, err := e.getDirectoryUser(ctx)
	if err != nil {
		return nil, err
	}
	if groupIDs, ok := getStructStringSlice(du, "group_ids"); ok {
		return groupIDs, nil
	}
	return make([]string, 0), nil
}

func (e *headersEvaluatorEvaluation) getJWTPayloadIss() string {
	return e.request.Issuer
}

func (e *headersEvaluatorEvaluation) getJWTPayloadAud() string {
	return e.request.Audience
}

func (e *headersEvaluatorEvaluation) getJWTPayloadJTI() string {
	if e.gotJWTPayloadJTI {
		return e.cachedJWTPayloadJTI
	}

	e.gotJWTPayloadJTI = true
	e.cachedJWTPayloadJTI = uuid.New().String()
	return e.cachedJWTPayloadJTI
}

func (e *headersEvaluatorEvaluation) getJWTPayloadIAT() int64 {
	return e.now.Unix()
}

func (e *headersEvaluatorEvaluation) getJWTPayloadExp() int64 {
	return e.now.Add(5 * time.Minute).Unix()
}

func (e *headersEvaluatorEvaluation) getJWTPayloadSub(ctx context.Context) (string, error) {
	return e.getJWTPayloadUser(ctx)
}

func (e *headersEvaluatorEvaluation) getJWTPayloadUser(ctx context.Context) (string, error) {
	s, sa, err := e.getSessionOrServiceAccount(ctx)
	if err != nil {
		return "", err
	}
	if sa != nil {
		return sa.UserId, nil
	}

	if s != nil {
		return s.UserId, nil
	}

	return "", nil
}

func (e *headersEvaluatorEvaluation) getJWTPayloadEmail(ctx context.Context) (string, error) {
	du, err := e.getDirectoryUser(ctx)
	if err != nil {
		return "", err
	}
	if v, ok := getStructString(du, "email"); ok {
		return v, nil
	}

	u, err := e.getUser(ctx)
	if err != nil {
		return "", err
	}
	if u != nil {
		return u.Email, nil
	}

	return "", nil
}

func (e *headersEvaluatorEvaluation) getJWTPayloadGroups(ctx context.Context) ([]string, error) {
	groupIDs, err := e.getGroupIDs(ctx)
	if err != nil {
		return nil, err
	}
	if len(groupIDs) > 0 {
		groups := make([]string, 0, len(groupIDs)*2)
		groups = append(groups, groupIDs...)
		groupNames, err := e.getDataBrokerGroupNames(ctx, groupIDs)
		if err != nil {
			return nil, err
		}
		groups = append(groups, groupNames...)
		return groups, nil
	}

	s, _, err := e.getSessionOrServiceAccount(ctx)
	if err != nil {
		return nil, err
	}
	groups, _ := getClaimStringSlice(s, "groups")
	return groups, nil
}

func (e *headersEvaluatorEvaluation) getJWTPayloadSID() string {
	return e.request.Session.ID
}

func (e *headersEvaluatorEvaluation) getJWTPayloadName(ctx context.Context) (string, error) {
	s, _, err := e.getSessionOrServiceAccount(ctx)
	if err != nil {
		return "", err
	}
	if names, ok := getClaimStringSlice(s, "name"); ok {
		return strings.Join(names, ","), nil
	}

	u, err := e.getUser(ctx)
	if err != nil {
		return "", err
	}
	if names, ok := getClaimStringSlice(u, "name"); ok {
		return strings.Join(names, ","), nil
	}

	return "", nil
}

func (e *headersEvaluatorEvaluation) getJWTPayload(ctx context.Context) (map[string]any, error) {
	if e.gotJWTPayload {
		return e.cachedJWTPayload, nil
	}

	e.cachedJWTPayload = map[string]any{
		"iss": e.getJWTPayloadIss(),
		"aud": e.getJWTPayloadAud(),
		"jti": e.getJWTPayloadJTI(),
		"iat": e.getJWTPayloadIAT(),
		"exp": e.getJWTPayloadExp(),
		"sid": e.getJWTPayloadSID(),
	}

	var err error
	e.cachedJWTPayload["sub"], err = e.getJWTPayloadSub(ctx)
	if err != nil {
		return nil, err
	}
	e.cachedJWTPayload["user"], err = e.getJWTPayloadUser(ctx)
	if err != nil {
		return nil, err
	}
	e.cachedJWTPayload["email"], err = e.getJWTPayloadEmail(ctx)
	if err != nil {
		return nil, err
	}
	e.cachedJWTPayload["groups"], err = e.getJWTPayloadGroups(ctx)
	if err != nil {
		return nil, err
	}
	e.cachedJWTPayload["name"], err = e.getJWTPayloadName(ctx)
	if err != nil {
		return nil, err
	}

	s, _, err := e.getSessionOrServiceAccount(ctx)
	if err != nil {
		return nil, err
	}
	u, err := e.getUser(ctx)
	if err != nil {
		return nil, err
	}

	for _, claimKey := range e.evaluator.store.GetJWTClaimHeaders() {
		// ignore base claims
		if _, ok := e.cachedJWTPayload[claimKey]; ok {
			continue
		}

		if vs, ok := getClaimStringSlice(s, claimKey); ok {
			e.cachedJWTPayload[claimKey] = strings.Join(vs, ",")
		} else if vs, ok := getClaimStringSlice(u, claimKey); ok {
			e.cachedJWTPayload[claimKey] = strings.Join(vs, ",")
		}
	}

	e.gotJWTPayload = true
	return e.cachedJWTPayload, nil
}

func (e *headersEvaluatorEvaluation) getSignedJWT(ctx context.Context) (string, error) {
	if e.gotSignedJWT {
		return e.cachedSignedJWT, nil
	}

	signingKey := e.evaluator.store.GetSigningKey()
	if signingKey == nil {
		log.Ctx(ctx).Error().Msg("authorize/header-evaluator: missing signing key")
		return "", nil
	}

	signingOptions := new(jose.SignerOptions).
		WithType("JWT").
		WithHeader("kid", signingKey.KeyID).
		WithHeader("alg", signingKey.Algorithm)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(signingKey.Algorithm),
		Key:       signingKey.Key,
	}, signingOptions)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authorize/header-evaluator: error creating JWT signer")
		return "", err
	}

	jwtPayload, err := e.getJWTPayload(ctx)
	if err != nil {
		return "", err
	}
	bs, err := json.Marshal(jwtPayload)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authorize/header-evaluator: error marshaling JWT payload")
		return "", err
	}

	jwt, err := signer.Sign(bs)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authorize/header-evaluator: error signing JWT")
		return "", err
	}

	e.cachedSignedJWT, err = jwt.CompactSerialize()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authorize/header-evaluator: error serializing JWT")
		return "", err
	}

	e.gotSignedJWT = true
	return e.cachedSignedJWT, nil
}

func (e *headersEvaluatorEvaluation) getDataBrokerGroupNames(ctx context.Context, groupIDs []string) ([]string, error) {
	groupNames := make([]string, 0, len(groupIDs))
	for _, groupID := range groupIDs {
		msg, err := e.evaluator.store.GetDataBrokerRecord(ctx, directory.GroupRecordType, groupID)
		if err != nil {
			return nil, fmt.Errorf("error looking up directory group: %w", err)
		}
		dg, _ := msg.(*structpb.Struct)
		if name, ok := getStructString(dg, "name"); ok {
			groupNames = append(groupNames, name)
		}
	}
	return groupNames, nil
}

type hasGetClaims interface {
	GetClaims() map[string]*structpb.ListValue
}

func getClaimStringSlice(msg hasGetClaims, field string) ([]string, bool) {
	if msg == nil {
		return nil, false
	}

	claims := msg.GetClaims()
	if claims == nil {
		return nil, false
	}

	lv, ok := claims[field]
	if !ok {
		return nil, false
	}

	strs := make([]string, 0, len(lv.Values))
	for _, v := range lv.Values {
		switch v := v.GetKind().(type) {
		case *structpb.Value_NumberValue:
			strs = append(strs, fmt.Sprint(v.NumberValue))
		case *structpb.Value_StringValue:
			strs = append(strs, v.StringValue)
		case *structpb.Value_BoolValue:
			strs = append(strs, fmt.Sprint(v.BoolValue))

		// just ignore these types
		case *structpb.Value_NullValue:
		case *structpb.Value_StructValue:
		case *structpb.Value_ListValue:
		}
	}
	return strs, true
}

func getStructString(s *structpb.Struct, field string) (string, bool) {
	if s == nil || s.Fields == nil {
		return "", false
	}

	v, ok := s.Fields[field]
	if !ok {
		return "", false
	}

	return fmt.Sprint(v.AsInterface()), true
}

func getStructStringSlice(s *structpb.Struct, field string) ([]string, bool) {
	if s == nil || s.Fields == nil {
		return nil, false
	}
	v, ok := s.Fields[field]
	if !ok {
		return nil, false
	}

	lv := v.GetListValue()
	if lv == nil {
		return nil, false
	}

	strs := make([]string, len(lv.Values))
	for i, vv := range lv.Values {
		sv, ok := vv.Kind.(*structpb.Value_StringValue)
		if !ok {
			return nil, false
		}
		strs[i] = sv.StringValue
	}
	return strs, true
}

func cryptoSHA256[T string | []byte](input T) string {
	output := sha256.Sum256([]byte(input))
	return hex.EncodeToString(output[:])
}

func getHeaderStringValue(obj any) string {
	v := reflect.ValueOf(obj)
	switch v.Kind() {
	case reflect.Slice:
		var str strings.Builder
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				str.WriteByte(',')
			}
			str.WriteString(getHeaderStringValue(v.Index(i).Interface()))
		}
		return str.String()
	}

	return fmt.Sprint(obj)
}
