package hpke

import (
	"fmt"
	"net/url"
)

// URL Parameters
const (
	ParamSenderPublicKey = "pomerium_hpke_sender_pub"
	ParamQuery           = "pomerium_hpke_query"
)

// IsEncryptedURL returns true if the url.Values contain an HPKE encrypted query.
func IsEncryptedURL(values url.Values) bool {
	return values.Has(ParamSenderPublicKey) && values.Has(ParamQuery)
}

// EncryptURLValues encrypts URL values using the Seal method.
func EncryptURLValues(
	senderPrivateKey *PrivateKey,
	receiverPublicKey *PublicKey,
	values url.Values,
) (encrypted url.Values, err error) {
	values = withoutHPKEParams(values)

	sealed, err := Seal(senderPrivateKey, receiverPublicKey, []byte(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("hpke: failed to seal URL values %w", err)
	}

	return url.Values{
		ParamSenderPublicKey: {senderPrivateKey.PublicKey().String()},
		ParamQuery:           {encode(sealed)},
	}, nil
}

// DecryptURLValues decrypts URL values using the Open method.
func DecryptURLValues(
	receiverPrivateKey *PrivateKey,
	encrypted url.Values,
) (senderPublicKey *PublicKey, values url.Values, err error) {
	if !encrypted.Has(ParamSenderPublicKey) {
		return nil, nil, fmt.Errorf("hpke: missing sender public key in query parameters")
	}
	if !encrypted.Has(ParamQuery) {
		return nil, nil, fmt.Errorf("hpke: missing encrypted query in query parameters")
	}

	senderPublicKey, err = PublicKeyFromString(encrypted.Get(ParamSenderPublicKey))
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: invalid sender public key parameter: %w", err)
	}

	sealed, err := decode(encrypted.Get(ParamQuery))
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: failed decoding query parameter: %w", err)
	}

	message, err := Open(receiverPrivateKey, senderPublicKey, sealed)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: failed to open sealed message: %w", err)
	}

	decrypted, err := url.ParseQuery(string(message))
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: invalid query parameter: %w", err)
	}

	values = withoutHPKEParams(encrypted)
	for k, vs := range decrypted {
		values[k] = vs
	}

	return senderPublicKey, values, err
}

func withoutHPKEParams(values url.Values) url.Values {
	filtered := make(url.Values)
	for k, vs := range values {
		if k != ParamSenderPublicKey && k != ParamQuery {
			filtered[k] = vs
		}
	}
	return filtered
}
