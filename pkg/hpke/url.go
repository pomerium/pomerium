package hpke

import (
	"fmt"
	"net/url"

	"github.com/klauspost/compress/zstd"
)

// URL Parameters
const (
	paramSenderPublicKey = "pomerium_hpke_sender_pub"
	paramQuery           = "pomerium_hpke_query"

	paramSenderPublicKeyV2 = "k"
	paramQueryV2           = "q"
)

var zstdEncoder *zstd.Encoder
var zstdDecoder *zstd.Decoder

func init() {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		panic(err)
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(0))
	if err != nil {
		panic(err)
	}
	zstdEncoder = enc
	zstdDecoder = dec
}

// IsEncryptedURL returns true if the url.Values contain an HPKE encrypted query.
func IsEncryptedURL(values url.Values) bool {
	return IsEncryptedURLV1(values) || IsEncryptedURLV2(values)
}

// IsEncryptedURLV1 returns true if the url.Values contain a V1 HPKE encrypted query.
func IsEncryptedURLV1(values url.Values) bool {
	return values.Has(paramSenderPublicKey) && values.Has(paramQuery)
}

// IsEncryptedURLV2 returns true if the url.Values contains a V2 HPKE encrypted query.
func IsEncryptedURLV2(values url.Values) bool {
	return values.Has(paramSenderPublicKeyV2) && values.Has(paramQueryV2)
}

// An EncryptURLValuesFunc is a function that encrypts url values.
type EncryptURLValuesFunc func(senderPrivateKey *PrivateKey, receiverPublicKey *PublicKey, values url.Values) (encrypted url.Values, err error)

// EncryptURLValuesV1 encrypts URL values using the Seal method.
func EncryptURLValuesV1(
	senderPrivateKey *PrivateKey,
	receiverPublicKey *PublicKey,
	values url.Values,
) (encrypted url.Values, err error) {
	values = withoutHPKEParams(values)

	encoded := encodeQueryStringV1(values)

	sealed, err := Seal(senderPrivateKey, receiverPublicKey, encoded)
	if err != nil {
		return nil, fmt.Errorf("hpke: failed to seal URL values %w", err)
	}

	return url.Values{
		paramSenderPublicKey: {senderPrivateKey.PublicKey().String()},
		paramQuery:           {encode(sealed)},
	}, nil
}

// EncryptURLValuesV2 encrypts URL values using the Seal method and compresses the query string.
func EncryptURLValuesV2(
	senderPrivateKey *PrivateKey,
	receiverPublicKey *PublicKey,
	values url.Values,
) (encrypted url.Values, err error) {
	values = withoutHPKEParams(values)

	encoded := encodeQueryStringV2(values)

	sealed, err := Seal(senderPrivateKey, receiverPublicKey, encoded)
	if err != nil {
		return nil, fmt.Errorf("hpke: failed to seal URL values %w", err)
	}

	return url.Values{
		paramSenderPublicKeyV2: {senderPrivateKey.PublicKey().String()},
		paramQueryV2:           {encode(sealed)},
	}, nil
}

// DecryptURLValues decrypts URL values using the Open method.
func DecryptURLValues(
	receiverPrivateKey *PrivateKey,
	encrypted url.Values,
) (senderPublicKey *PublicKey, values url.Values, err error) {
	var decrypted url.Values
	switch {
	case IsEncryptedURLV1(encrypted):
		senderPublicKey, err = PublicKeyFromString(encrypted.Get(paramSenderPublicKey))
		if err != nil {
			return nil, nil, fmt.Errorf("hpke: invalid sender public key parameter: %w", err)
		}

		sealed, err := decode(encrypted.Get(paramQuery))
		if err != nil {
			return nil, nil, fmt.Errorf("hpke: failed decoding query parameter: %w", err)
		}

		message, err := Open(receiverPrivateKey, senderPublicKey, sealed)
		if err != nil {
			return nil, nil, fmt.Errorf("hpke: failed to open sealed message: %w", err)
		}

		decrypted, err = decodeQueryStringV1(message)
		if err != nil {
			return nil, nil, fmt.Errorf("hpke: invalid query parameter: %w", err)
		}
	case IsEncryptedURLV2(encrypted):
		senderPublicKey, err = PublicKeyFromString(encrypted.Get(paramSenderPublicKeyV2))
		if err != nil {
			return nil, nil, fmt.Errorf("hpke: invalid sender public key parameter: %w", err)
		}

		sealed, err := decode(encrypted.Get(paramQueryV2))
		if err != nil {
			return nil, nil, fmt.Errorf("hpke: failed decoding query parameter: %w", err)
		}

		message, err := Open(receiverPrivateKey, senderPublicKey, sealed)
		if err != nil {
			return nil, nil, fmt.Errorf("hpke: failed to open sealed message: %w", err)
		}

		decrypted, err = decodeQueryStringV2(message)
		if err != nil {
			return nil, nil, fmt.Errorf("hpke: invalid query parameter: %w", err)
		}
	default:
		return nil, nil, fmt.Errorf("hpke: missing query parameters")
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
		if k != paramSenderPublicKey && k != paramQuery && k != paramSenderPublicKeyV2 && k != paramQueryV2 {
			filtered[k] = vs
		}
	}
	return filtered
}

func encodeQueryStringV1(values url.Values) []byte {
	return []byte(values.Encode())
}

func encodeQueryStringV2(values url.Values) []byte {
	return zstdEncoder.EncodeAll([]byte(values.Encode()), nil)
}

func decodeQueryStringV1(raw []byte) (url.Values, error) {
	return url.ParseQuery(string(raw))
}

func decodeQueryStringV2(raw []byte) (url.Values, error) {
	bs, err := zstdDecoder.DecodeAll(raw, nil)
	if err != nil {
		return nil, err
	}
	return url.ParseQuery(string(bs))
}
