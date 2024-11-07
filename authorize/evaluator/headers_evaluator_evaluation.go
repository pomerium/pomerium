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
	e.fillHeaders(ctx)
	return e.response, nil
}

func (e *headersEvaluatorEvaluation) fillJWTAssertionHeader(ctx context.Context) {
	e.response.Headers.Add("x-pomerium-jwt-assertion", e.getSignedJWT(ctx))
}

func (e *headersEvaluatorEvaluation) fillJWTClaimHeaders(ctx context.Context) {
	claims := e.getJWTPayload(ctx)
	for headerName, claimKey := range e.evaluator.store.GetJWTClaimHeaders() {
		claim, ok := claims[claimKey]
		if !ok {
			e.response.Headers.Add(headerName, "")
			continue
		}
		e.response.Headers.Add(headerName, getHeaderStringValue(claim))
	}
}

func (e *headersEvaluatorEvaluation) fillKubernetesHeaders(ctx context.Context) {
	if e.request.KubernetesServiceAccountToken == "" {
		return
	}

	e.response.Headers.Add("Authorization", "Bearer "+e.request.KubernetesServiceAccountToken)
	impersonateUser := e.getJWTPayloadEmail(ctx)
	if impersonateUser != "" {
		e.response.Headers.Add("Impersonate-User", impersonateUser)
	}
	impersonateGroups := e.getJWTPayloadGroups(ctx)
	if len(impersonateGroups) > 0 {
		e.response.Headers.Add("Impersonate-Group", strings.Join(impersonateGroups, ","))
	}
}

func (e *headersEvaluatorEvaluation) fillGoogleCloudServerlessHeaders(ctx context.Context) {
	if e.request.EnableGoogleCloudServerlessAuthentication {
		h, err := getGoogleCloudServerlessHeaders(e.evaluator.store.GetGoogleCloudServerlessAuthenticationServiceAccount(), e.request.ToAudience)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("authorize/header-evaluator: error retrieving google cloud serverless headers")
			return
		}
		for k, v := range h {
			e.response.Headers.Add(k, v)
		}
	}
}

func (e *headersEvaluatorEvaluation) fillRoutingKeyHeaders() {
	if e.request.EnableRoutingKey {
		e.response.Headers.Add("x-pomerium-routing-key", cryptoSHA256(e.request.Session.ID))
	}
}

func (e *headersEvaluatorEvaluation) fillSetRequestHeaders(ctx context.Context) {
	for k, v := range e.request.SetRequestHeaders {
		e.response.Headers.Add(k, os.Expand(v, func(name string) string {
			switch name {
			case "$":
				return "$"
			case "pomerium.access_token":
				s, _ := e.getSessionOrServiceAccount(ctx)
				return s.GetOauthToken().GetAccessToken()
			case "pomerium.client_cert_fingerprint":
				return e.getClientCertFingerprint()
			case "pomerium.id_token":
				s, _ := e.getSessionOrServiceAccount(ctx)
				return s.GetIdToken().GetRaw()
			case "pomerium.jwt":
				return e.getSignedJWT(ctx)
			}

			return ""
		}))
	}
}

func (e *headersEvaluatorEvaluation) fillHeaders(ctx context.Context) {
	e.fillJWTAssertionHeader(ctx)
	e.fillJWTClaimHeaders(ctx)
	e.fillKubernetesHeaders(ctx)
	e.fillGoogleCloudServerlessHeaders(ctx)
	e.fillRoutingKeyHeaders()
	e.fillSetRequestHeaders(ctx)
}

func (e *headersEvaluatorEvaluation) getSessionOrServiceAccount(ctx context.Context) (*session.Session, *user.ServiceAccount) {
	if e.gotSessionOrServiceAccount {
		return e.cachedSession, e.cachedServiceAccount
	}

	e.gotSessionOrServiceAccount = true
	if e.request.Session.ID != "" {
		e.cachedServiceAccount, _ = e.evaluator.store.GetDataBrokerRecord(ctx, "type.googleapis.com/user.ServiceAccount", e.request.Session.ID).(*user.ServiceAccount)
	}

	if e.request.Session.ID != "" && e.cachedServiceAccount == nil {
		e.cachedSession, _ = e.evaluator.store.GetDataBrokerRecord(ctx, "type.googleapis.com/session.Session", e.request.Session.ID).(*session.Session)
	}
	if e.cachedSession != nil && e.cachedSession.GetImpersonateSessionId() != "" {
		e.cachedSession, _ = e.evaluator.store.GetDataBrokerRecord(ctx, "type.googleapis.com/session.Session", e.cachedSession.GetImpersonateSessionId()).(*session.Session)
	}
	return e.cachedSession, e.cachedServiceAccount
}

func (e *headersEvaluatorEvaluation) getUser(ctx context.Context) *user.User {
	if e.gotUser {
		return e.cachedUser
	}

	e.gotUser = true
	s, sa := e.getSessionOrServiceAccount(ctx)
	if sa != nil && sa.UserId != "" {
		e.cachedUser, _ = e.evaluator.store.GetDataBrokerRecord(ctx, "type.googleapis.com/user.User", sa.UserId).(*user.User)
	} else if s != nil && s.UserId != "" {
		e.cachedUser, _ = e.evaluator.store.GetDataBrokerRecord(ctx, "type.googleapis.com/user.User", s.UserId).(*user.User)
	}
	return e.cachedUser
}

func (e *headersEvaluatorEvaluation) getClientCertFingerprint() string {
	cert, err := cryptutil.ParsePEMCertificate([]byte(e.request.ClientCertificate.Leaf))
	if err != nil {
		return ""
	}
	return cryptoSHA256(cert.Raw)
}

func (e *headersEvaluatorEvaluation) getDirectoryUser(ctx context.Context) *structpb.Struct {
	if e.gotDirectoryUser {
		return e.cachedDirectoryUser
	}

	e.gotDirectoryUser = true
	s, sa := e.getSessionOrServiceAccount(ctx)
	if sa != nil && sa.UserId != "" {
		e.cachedDirectoryUser, _ = e.evaluator.store.GetDataBrokerRecord(ctx, directory.UserRecordType, sa.UserId).(*structpb.Struct)
	} else if s != nil && s.UserId != "" {
		e.cachedDirectoryUser, _ = e.evaluator.store.GetDataBrokerRecord(ctx, directory.UserRecordType, s.UserId).(*structpb.Struct)
	}
	return e.cachedDirectoryUser
}

func (e *headersEvaluatorEvaluation) getGroupIDs(ctx context.Context) []string {
	du := e.getDirectoryUser(ctx)
	if groupIDs, ok := getStructStringSlice(du, "group_ids"); ok {
		return groupIDs
	}
	return make([]string, 0)
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

func (e *headersEvaluatorEvaluation) getJWTPayloadSub(ctx context.Context) string {
	return e.getJWTPayloadUser(ctx)
}

func (e *headersEvaluatorEvaluation) getJWTPayloadUser(ctx context.Context) string {
	s, sa := e.getSessionOrServiceAccount(ctx)
	if sa != nil {
		return sa.UserId
	}

	if s != nil {
		return s.UserId
	}

	return ""
}

func (e *headersEvaluatorEvaluation) getJWTPayloadEmail(ctx context.Context) string {
	du := e.getDirectoryUser(ctx)
	if v, ok := getStructString(du, "email"); ok {
		return v
	}

	u := e.getUser(ctx)
	if u != nil {
		return u.Email
	}

	return ""
}

func (e *headersEvaluatorEvaluation) getJWTPayloadGroups(ctx context.Context) []string {
	groupIDs := e.getGroupIDs(ctx)
	if len(groupIDs) > 0 {
		groups := make([]string, 0, len(groupIDs)*2)
		groups = append(groups, groupIDs...)
		groups = append(groups, e.getDataBrokerGroupNames(ctx, groupIDs)...)
		return groups
	}

	s, _ := e.getSessionOrServiceAccount(ctx)
	groups, _ := getClaimStringSlice(s, "groups")
	return groups
}

func (e *headersEvaluatorEvaluation) getJWTPayloadSID() string {
	return e.request.Session.ID
}

func (e *headersEvaluatorEvaluation) getJWTPayloadName(ctx context.Context) string {
	s, _ := e.getSessionOrServiceAccount(ctx)
	if names, ok := getClaimStringSlice(s, "name"); ok {
		return strings.Join(names, ",")
	}

	u := e.getUser(ctx)
	if names, ok := getClaimStringSlice(u, "name"); ok {
		return strings.Join(names, ",")
	}

	return ""
}

func (e *headersEvaluatorEvaluation) getJWTPayload(ctx context.Context) map[string]any {
	if e.gotJWTPayload {
		return e.cachedJWTPayload
	}

	e.gotJWTPayload = true
	e.cachedJWTPayload = map[string]any{
		"iss":    e.getJWTPayloadIss(),
		"aud":    e.getJWTPayloadAud(),
		"jti":    e.getJWTPayloadJTI(),
		"iat":    e.getJWTPayloadIAT(),
		"exp":    e.getJWTPayloadExp(),
		"sub":    e.getJWTPayloadSub(ctx),
		"user":   e.getJWTPayloadUser(ctx),
		"email":  e.getJWTPayloadEmail(ctx),
		"groups": e.getJWTPayloadGroups(ctx),
		"sid":    e.getJWTPayloadSID(),
		"name":   e.getJWTPayloadName(ctx),
	}

	s, _ := e.getSessionOrServiceAccount(ctx)
	u := e.getUser(ctx)

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
	return e.cachedJWTPayload
}

func (e *headersEvaluatorEvaluation) getSignedJWT(ctx context.Context) string {
	if e.gotSignedJWT {
		return e.cachedSignedJWT
	}

	e.gotSignedJWT = true
	signingKey := e.evaluator.store.GetSigningKey()
	if signingKey == nil {
		log.Ctx(ctx).Error().Msg("authorize/header-evaluator: missing signing key")
		return ""
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
		return ""
	}

	jwtPayload := e.getJWTPayload(ctx)
	bs, err := json.Marshal(jwtPayload)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authorize/header-evaluator: error marshaling JWT payload")
		return ""
	}

	jwt, err := signer.Sign(bs)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authorize/header-evaluator: error signing JWT")
		return ""
	}

	e.cachedSignedJWT, err = jwt.CompactSerialize()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authorize/header-evaluator: error serializing JWT")
		return ""
	}
	return e.cachedSignedJWT
}

func (e *headersEvaluatorEvaluation) getDataBrokerGroupNames(ctx context.Context, groupIDs []string) []string {
	groupNames := make([]string, 0, len(groupIDs))
	for _, groupID := range groupIDs {
		dg, _ := e.evaluator.store.GetDataBrokerRecord(ctx, directory.GroupRecordType, groupID).(*structpb.Struct)
		if name, ok := getStructString(dg, "name"); ok {
			groupNames = append(groupNames, name)
		}
	}
	return groupNames
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
