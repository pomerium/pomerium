package session

import (
	"fmt"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

type handleExtraClaims struct {
	IdentityProviderID      string `json:"idp_id,omitempty"`
	DataBrokerServerVersion uint64 `json:"databroker_server_version,omitempty"`
	DataBrokerRecordVersion uint64 `json:"databroker_record_version,omitempty"`
}

func MarshalAndSignHandle(key []byte, h *Handle) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       key,
	}, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("error creating session handle signer: %w", err)
	}

	m := map[string]any{}
	if v := h.Id; v != "" {
		m["jti"] = v
	}
	if v := h.UserId; v != "" {
		m["sub"] = v
	}
	if v := h.Audience; len(v) == 1 {
		m["aud"] = v[0]
	} else if len(v) > 1 {
		m["aud"] = v
	}
	if v := h.IdpId; v != "" {
		m["idp_id"] = v
	}
	if v := h.DataBrokerServerVersion; v > 0 {
		m["databroker_server_version"] = v
	}
	if v := h.DataBrokerRecordVersion; v > 0 {
		m["databroker_record_version"] = v
	}

	base := jwt.Claims{
		Subject:  h.UserId,
		Audience: h.Audience,
		ID:       h.Id,
	}
	extra := handleExtraClaims{
		IdentityProviderID:      h.IdpId,
		DataBrokerServerVersion: h.DataBrokerServerVersion,
		DataBrokerRecordVersion: h.DataBrokerRecordVersion,
	}

	str, err := jwt.Signed(signer).Claims(base).Claims(extra).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("error marshaling jwt: %w", err)
	}

	return str, nil
}

func UnmarshalAndVerifyHandle(key []byte, str string) (*Handle, error) {
	t, err := jwt.ParseSigned(str)
	if err != nil {
		return nil, err
	}

	var base jwt.Claims
	var extra handleExtraClaims
	err = t.Claims(key, &base, &extra)
	if err != nil {
		return nil, err
	}

	h := new(Handle)
	h.Id = base.ID
	h.UserId = base.Subject
	h.Audience = base.Audience
	h.IdpId = extra.IdentityProviderID
	h.DataBrokerServerVersion = extra.DataBrokerServerVersion
	h.DataBrokerRecordVersion = extra.DataBrokerRecordVersion
	return h, nil
}
