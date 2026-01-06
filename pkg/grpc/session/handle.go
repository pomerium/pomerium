package session

import (
	"encoding/json"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/volatiletech/null/v9"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NewHandle creates a new handle.
func NewHandle(identityProviderID string) *Handle {
	return &Handle{
		Id:                 uuid.New().String(),
		IdentityProviderId: identityProviderID,
		Iat:                timestamppb.Now(),
	}
}

func (x *Handle) MarshalJSON() ([]byte, error) {
	m := map[string]any{}

	// standard claims

	if x.Iss != nil {
		m["iss"] = *x.Iss
	}
	if x.UserId != "" {
		m["sub"] = x.UserId
	}
	if len(x.Aud) > 0 {
		m["aud"] = x.Aud
	}
	if x.Exp != nil {
		m["exp"] = jwt.NewNumericDate(x.Exp.AsTime())
	}
	if x.Nbf != nil {
		m["nbf"] = jwt.NewNumericDate(x.Nbf.AsTime())
	}
	if x.Iat != nil {
		m["iat"] = jwt.NewNumericDate(x.Iat.AsTime())
	}
	if x.Id != "" {
		m["jti"] = x.Id
	}

	// extra claims

	if x.IdentityProviderId != "" {
		m["idp_id"] = x.IdentityProviderId
	}
	if x.DatabrokerServerVersion != nil {
		m["databroker_server_version"] = *x.DatabrokerServerVersion
	}
	if x.DatabrokerRecordVersion != nil {
		m["databroker_record_version"] = *x.DatabrokerRecordVersion
	}

	return json.Marshal(m)
}

func (x *Handle) UnmarshalJSON(data []byte) error {
	// unmarshal from the custom format
	var claims struct {
		// standard claims

		Issuer    null.String      `json:"iss,omitzero"`
		Subject   null.String      `json:"sub,omitzero"`
		Audience  jwt.Audience     `json:"aud,omitzero"`
		Expiry    *jwt.NumericDate `json:"exp,omitzero"`
		NotBefore *jwt.NumericDate `json:"nbf,omitzero"`
		IssuedAt  *jwt.NumericDate `json:"iat,omitzero"`
		JTI       null.String      `json:"jti,omitzero"`

		// special claims

		ObjectID null.String `json:"oid,omitzero"` // for azure

		// custom claims

		IdentityProviderID      null.String `json:"idp_id,omitzero"`
		DatabrokerServerVersion null.Uint64 `json:"databroker_server_version,omitzero"`
		DatabrokerRecordVersion null.Uint64 `json:"databroker_record_version,omitzero"`
	}
	err := json.Unmarshal(data, &claims)
	if err != nil {
		return err
	}

	// fill in the data
	if claims.Issuer.IsSet() {
		x.Iss = claims.Issuer.Ptr()
	}
	if claims.Subject.IsValid() {
		x.UserId = claims.Subject.String
	}
	if len(claims.Audience) > 0 {
		x.Aud = claims.Audience
	}
	if claims.Expiry != nil {
		x.Exp = timestamppb.New(claims.Expiry.Time())
	}
	if claims.NotBefore != nil {
		x.Nbf = timestamppb.New(claims.NotBefore.Time())
	}
	if claims.IssuedAt != nil {
		x.Iat = timestamppb.New(claims.IssuedAt.Time())
	}
	if claims.JTI.IsValid() {
		x.Id = claims.JTI.String
	}
	if claims.ObjectID.IsValid() {
		x.UserId = claims.ObjectID.String
	}
	if claims.IdentityProviderID.IsValid() {
		x.IdentityProviderId = claims.IdentityProviderID.String
	}
	if claims.DatabrokerServerVersion.IsSet() {
		x.DatabrokerServerVersion = claims.DatabrokerServerVersion.Ptr()
	}
	if claims.DatabrokerRecordVersion.IsSet() {
		x.DatabrokerRecordVersion = claims.DatabrokerRecordVersion.Ptr()
	}

	return nil
}

func (x *Handle) WithNewIssuer(issuer string, audience jwt.Audience) *Handle {
	y := proto.CloneOf(x)
	y.Iss = proto.String(issuer)
	y.Aud = audience
	y.Iat = timestamppb.Now()
	return y
}
