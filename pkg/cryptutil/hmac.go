package cryptutil

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"strconv"
	"time"
)

const (
	// DefaultLeeway defines the default leeway for matching NotBefore/Expiry claims.
	DefaultLeeway = 5.0 * time.Minute
)

var (
	errTimestampMalformed = errors.New("internal/cryptutil: timestamp malformed")
	errTimestampExpired   = errors.New("internal/cryptutil: timestamp expired")
	errTimestampTooSoon   = errors.New("internal/cryptutil: timestamp too soon")
)

// GenerateHMAC produces a symmetric signature using a shared secret key.
func GenerateHMAC(data []byte, key string) []byte {
	h := hmac.New(sha512.New512_256, []byte(key))
	h.Write(data)
	return h.Sum(nil)

}

// CheckHMAC securely checks the supplied MAC against a message using the
// shared secret key.
func CheckHMAC(data, suppliedMAC []byte, key string) bool {
	expectedMAC := GenerateHMAC(data, key)
	return hmac.Equal(expectedMAC, suppliedMAC)
}

// ValidTimestamp is a helper function often used in conjunction with an HMAC
// function to verify that the timestamp (in unix seconds) is within leeway
// period.
func ValidTimestamp(ts string) error {
	var timeStamp int64
	var err error
	if timeStamp, err = strconv.ParseInt(ts, 10, 64); err != nil {
		return errTimestampMalformed
	}
	// unix time in seconds
	tm := time.Unix(timeStamp, 0)
	if time.Since(tm) > DefaultLeeway {
		return errTimestampExpired
	}
	if time.Until(tm) > DefaultLeeway {
		return errTimestampTooSoon
	}
	return nil
}
